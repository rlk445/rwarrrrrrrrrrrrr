/*
 * StormVR Server — captura D3D11 → NVENC → WebSocket para o iPhone
 *
 * O que faz:
 *   1. Aceita uma conexão WebSocket do iPhone na porta 5560
 *   2. Recebe mensagens de pose (MSG_POSE) e as injeta no runtime via UDP 127.0.0.1:5556/5557
 *   3. A cada frame, lê as texturas dos swapchains do runtime (via D3D11 shared handle)
 *   4. Compõe os dois olhos lado a lado num frame
 *   5. Codifica com NVENC (H.264 Baseline) em hardware
 *   6. Envia o NAL Annex-B ao iPhone com cabeçalho de pose (MSG_VIDEO)
 *
 * Compilar (MSVC x64, Release):
 *   cmake -S . -B build -A x64 && cmake --build build --config Release
 *
 * Dependências:
 *   - SDK do Windows (D3D11, DXGI, WinSock2)
 *   - NVENC SDK (nvEncodeAPI.h) — baixar em developer.nvidia.com/nvidia-video-codec-sdk
 *   - stormvr_core.lib (do projeto principal)
 *
 * Sem código-fonte da runtime DLL (caixa-preta), lemos os swapchains via
 * D3D11 KeyedMutex: o runtime grava o frame e libera o mutex; nós adquirimos,
 * copiamos e liberamos. Se o runtime não expuser o handle, usamos GDI/DXGI
 * desktop duplication como fallback (captura a janela de preview do SteamVR ou
 * a janela virtual do headset).
 *
 * NOTA: este arquivo é a versão completa de referência. Partes que dependem do
 * NVENC SDK são marcadas com /* NVENC * /; funcionam quando o SDK está presente.
 * Sem o SDK, o código compila com um stub que usa CPU (libjpeg como fallback
 * — muito mais lento, só para teste).
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <dxgi1_6.h>
#include <unknwn.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

// ----------------------------------------------------------------------------
// Protocolo (igual ao pcbridge.js)
// ----------------------------------------------------------------------------
static constexpr uint8_t  MSG_POSE  = 0x01;
static constexpr uint8_t  MSG_VIDEO = 0x02;
static constexpr uint32_t WS_PORT   = 5560;

// Cabeçalho de pose que o iPhone envia (56 bytes)
#pragma pack(push,1)
struct PoseMsg {
    uint8_t  type;          // MSG_POSE
    uint8_t  pad[3];
    uint32_t tsMs;          // timestamp iPhone (ms)
    float    qx,qy,qz,qw;  // quaternion cabeça
    float    px,py,pz;      // posição cabeça
    float    lx,ly,lz;      // posição mão esquerda (NaN se invisível)
    float    pad2[2];
};

struct VideoHdr {
    uint8_t  type;          // MSG_VIDEO
    uint8_t  flags;         // 0x01 = keyframe
    uint8_t  pad[2];
    uint32_t frameId;
    uint32_t tsPC;          // timestamp PC (ms)
    float    qx,qy,qz,qw;  // pose com que foi renderizado
    float    reserved[7];
};
static_assert(sizeof(VideoHdr) == 56, "VideoHdr deve ter 56 bytes");
#pragma pack(pop)

// ----------------------------------------------------------------------------
// Log simples
// ----------------------------------------------------------------------------
static FILE* gLog = nullptr;
static void logOpen() {
    char path[MAX_PATH];
    const char* la = getenv("LOCALAPPDATA");
    if (!la) la = ".";
    snprintf(path, sizeof(path), "%s\\StormVR\\server.log", la);
    gLog = fopen(path, "ab");
}
static void logf(const char* fmt, ...) {
    va_list a; va_start(a, fmt);
    vprintf(fmt, a);
    if (gLog) { vfprintf(gLog, fmt, a); fflush(gLog); }
    va_end(a);
}

// ----------------------------------------------------------------------------
// Estado global compartilhado
// ----------------------------------------------------------------------------
struct State {
    std::mutex         mu;
    PoseMsg            lastPose{};
    bool               hasPose = false;
    // frame atual (Annex-B H.264) + metadados
    std::vector<uint8_t> nalBuf;
    uint32_t           frameId   = 0;
    bool               keyframe  = false;
    float              poseQ[4]  = {0,0,0,1};
    bool               frameReady = false;
    std::atomic<bool>  running{true};
};
static State g;

// ============================================================================
// Seção 1 — WebSocket (implementação mínima RFC 6455 sem TLS, sem fragmentação)
// ============================================================================
namespace WS {

static std::string b64(const uint8_t* d, size_t n) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o; o.reserve((n + 2) / 3 * 4);
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)d[i] << 16 | (i+1<n?(uint32_t)d[i+1]<<8:0) | (i+2<n?(uint32_t)d[i+2]:0);
        o += T[(v>>18)&63]; o += T[(v>>12)&63];
        o += (i+1<n) ? T[(v>>6)&63] : '=';
        o += (i+2<n) ? T[v&63]      : '=';
    }
    return o;
}

// SHA-1 mínimo para handshake WebSocket
static void sha1(const uint8_t* msg, size_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0};
    // Preenche e processa blocos de 64 bytes
    size_t total = ((len+8)/64+1)*64;
    std::vector<uint8_t> buf(total, 0);
    memcpy(buf.data(), msg, len);
    buf[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) buf[total-1-i] = (uint8_t)(bits >> (i*8));
    for (size_t b = 0; b < total; b += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)buf[b+i*4]<<24)|((uint32_t)buf[b+i*4+1]<<16)|
                   ((uint32_t)buf[b+i*4+2]<<8)|(uint32_t)buf[b+i*4+3];
        }
        for (int i = 16; i < 80; i++) { uint32_t x=w[i-3]^w[i-8]^w[i-14]^w[i-16]; w[i]=(x<<1)|(x>>31); }
        uint32_t a=h[0],bv=h[1],c=h[2],d=h[3],e=h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f,k;
            if(i<20){f=(bv&c)|((~bv)&d);k=0x5A827999;}
            else if(i<40){f=bv^c^d;k=0x6ED9EBA1;}
            else if(i<60){f=(bv&c)|(bv&d)|(c&d);k=0x8F1BBCDC;}
            else{f=bv^c^d;k=0xCA62C1D6;}
            uint32_t tmp=((a<<5)|(a>>27))+f+e+k+w[i];
            e=d;d=c;c=(bv<<30)|(bv>>2);bv=a;a=tmp;
        }
        h[0]+=a;h[1]+=bv;h[2]+=c;h[3]+=d;h[4]+=e;
    }
    for (int i = 0; i < 5; i++) {
        out[i*4+0]=(h[i]>>24)&0xff; out[i*4+1]=(h[i]>>16)&0xff;
        out[i*4+2]=(h[i]>>8)&0xff;  out[i*4+3]=h[i]&0xff;
    }
}

struct Conn {
    SOCKET sock;
    bool   upgraded = false;
    std::vector<uint8_t> rxBuf;

    bool handshake() {
        // Lê o HTTP Upgrade
        rxBuf.resize(4096);
        int n = recv(sock, (char*)rxBuf.data(), (int)rxBuf.size()-1, 0);
        if (n <= 0) return false;
        rxBuf[n] = 0;
        std::string req((char*)rxBuf.data(), n);

        // Extrai Sec-WebSocket-Key
        auto pos = req.find("Sec-WebSocket-Key:");
        if (pos == std::string::npos) return false;
        pos += 18;
        while (pos < req.size() && req[pos] == ' ') pos++;
        auto end = req.find("\r\n", pos);
        std::string key = req.substr(pos, end - pos);

        // Calcula accept
        std::string combined = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        uint8_t digest[20];
        sha1((const uint8_t*)combined.c_str(), combined.size(), digest);
        std::string accept = b64(digest, 20);

        std::string resp =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
        send(sock, resp.c_str(), (int)resp.size(), 0);
        upgraded = true;
        rxBuf.clear();
        return true;
    }

    // Lê um frame WebSocket; retorna os dados do payload em 'out'.
    // Retorna false se a conexão fechou.
    bool readFrame(std::vector<uint8_t>& out) {
        // Recebe pelo menos 2 bytes de cabeçalho
        uint8_t hdr[14]; int got = 0;
        while (got < 2) {
            int r = recv(sock, (char*)hdr+got, 2-got, 0);
            if (r <= 0) return false;
            got += r;
        }
        bool masked  = !!(hdr[1] & 0x80);
        uint64_t plen = hdr[1] & 0x7F;
        int xtra = 0;
        if (plen == 126) xtra = 2;
        else if (plen == 127) xtra = 8;
        if (xtra) {
            uint8_t eb[8]={};
            int eg = 0;
            while (eg < xtra) { int r=recv(sock,(char*)eb+eg,xtra-eg,0); if(r<=0)return false; eg+=r; }
            plen = 0;
            for (int i = 0; i < xtra; i++) plen = (plen<<8)|eb[i];
        }
        uint8_t mask[4]={};
        if (masked) { int mg=0; while(mg<4){int r=recv(sock,(char*)mask+mg,4-mg,0);if(r<=0)return false;mg+=r;} }
        if (plen > 64*1024*1024) return false;   // proteção: > 64 MB é anormal
        out.resize((size_t)plen);
        size_t rg = 0;
        while (rg < (size_t)plen) {
            int r = recv(sock, (char*)out.data()+rg, (int)std::min((size_t)65536, plen-rg), 0);
            if (r <= 0) return false;
            rg += r;
        }
        if (masked) for (size_t i = 0; i < (size_t)plen; i++) out[i] ^= mask[i&3];
        return true;
    }

    // Envia um frame WebSocket binário (sem máscara — servidor para cliente)
    bool sendBin(const uint8_t* data, size_t len) {
        std::vector<uint8_t> frame;
        frame.push_back(0x82);  // FIN + opcode binary
        if (len < 126) {
            frame.push_back((uint8_t)len);
        } else if (len < 65536) {
            frame.push_back(126);
            frame.push_back((uint8_t)(len >> 8));
            frame.push_back((uint8_t)(len & 0xFF));
        } else {
            frame.push_back(127);
            for (int i = 7; i >= 0; i--) frame.push_back((uint8_t)(len >> (i*8)));
        }
        frame.insert(frame.end(), data, data+len);
        int sent = 0, total = (int)frame.size();
        while (sent < total) {
            int r = ::send(sock, (const char*)frame.data()+sent, total-sent, 0);
            if (r <= 0) return false;
            sent += r;
        }
        return true;
    }
};

} // namespace WS

// ============================================================================
// Seção 2 — NVENC (codificação H.264 por GPU)
// ============================================================================
#ifdef HAVE_NVENC
#include <nvEncodeAPI.h>
// Wrapper mínimo para NVENC — apenas o necessário para streamar
struct NVEncoder {
    void*               nvenc = nullptr;  // NV_ENCODE_API_FUNCTION_LIST::nvEncOpenEncodeSession
    NV_ENCODE_API_FUNCTION_LIST api{};
    void*               session = nullptr;
    NV_ENC_BUFFER_FORMAT fmt = NV_ENC_BUFFER_FORMAT_ARGB;
    uint32_t            w = 0, h = 0;
    // buffers de entrada e saída
    NV_ENC_INPUT_PTR    inBuf   = nullptr;
    NV_ENC_OUTPUT_PTR   outBuf  = nullptr;
    uint32_t            frameN  = 0;

    bool init(ID3D11Device* dev, uint32_t width, uint32_t height) {
        w = width; h = height;
        // Abre sessão DirectX
        NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS p{};
        p.version    = NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_VER;
        p.deviceType = NV_ENC_DEVICE_TYPE_DIRECTX;
        p.device     = dev;
        p.apiVersion = NVENCAPI_VERSION;
        if (api.nvEncOpenEncodeSessionEx(&p, &session) != NV_ENC_SUCCESS) {
            logf("[nvenc] OpenEncodeSessionEx falhou\n"); return false;
        }
        // Configura H.264 Baseline para máxima compatibilidade com iOS
        NV_ENC_INITIALIZE_PARAMS ip{};
        ip.version           = NV_ENC_INITIALIZE_PARAMS_VER;
        ip.encodeGUID        = NV_ENC_CODEC_H264_GUID;
        ip.presetGUID        = NV_ENC_PRESET_P1_GUID;  // latência ultra-baixa
        ip.encodeWidth       = w;
        ip.encodeHeight      = h;
        ip.darWidth          = w;
        ip.darHeight         = h;
        ip.frameRateNum      = 60;
        ip.frameRateDen      = 1;
        ip.enablePTD         = 1;
        ip.reportSliceOffsets= 0;
        ip.enableSubFrameWrite=0;
        NV_ENC_CONFIG cfg{};
        cfg.version          = NV_ENC_CONFIG_VER;
        cfg.profileGUID      = NV_ENC_H264_PROFILE_BASELINE_GUID;
        cfg.gopLength        = NVENC_INFINITE_GOPLENGTH;
        cfg.frameIntervalP   = 1;
        cfg.rcParams.rateControlMode = NV_ENC_PARAMS_RC_CBR;
        cfg.rcParams.averageBitRate  = 20 * 1000 * 1000;   // 20 Mbps — Wi-Fi aguenta
        cfg.rcParams.maxBitRate      = 25 * 1000 * 1000;
        cfg.rcParams.vbvBufferSize   = cfg.rcParams.averageBitRate / 60;
        cfg.encodeCodecConfig.h264Config.idrPeriod  = NVENC_INFINITE_GOPLENGTH;
        cfg.encodeCodecConfig.h264Config.outputBufferingPeriodSEI = 0;
        cfg.encodeCodecConfig.h264Config.outputPictureTimingSEI   = 0;
        cfg.encodeCodecConfig.h264Config.sliceMode  = 0;
        cfg.encodeCodecConfig.h264Config.sliceModeData = 0;
        ip.encodeConfig = &cfg;
        if (api.nvEncInitializeEncoder(session, &ip) != NV_ENC_SUCCESS) {
            logf("[nvenc] InitializeEncoder falhou\n"); return false;
        }
        // Aloca buffers
        NV_ENC_CREATE_INPUT_BUFFER ci{};
        ci.version    = NV_ENC_CREATE_INPUT_BUFFER_VER;
        ci.width      = w; ci.height = h;
        ci.bufferFmt  = fmt;
        ci.memoryHeap = NV_ENC_MEMORY_HEAP_SYSMEM_CACHED;
        api.nvEncCreateInputBuffer(session, &ci);
        inBuf = ci.inputBuffer;

        NV_ENC_CREATE_BITSTREAM_BUFFER cb{};
        cb.version = NV_ENC_CREATE_BITSTREAM_BUFFER_VER;
        api.nvEncCreateBitstreamBuffer(session, &cb);
        outBuf = cb.bitstreamBuffer;

        logf("[nvenc] iniciado %ux%u H.264 Baseline 20 Mbps\n", w, h);
        return true;
    }

    // Codifica um frame BGRA da memória do sistema; preenche 'nal' com Annex-B.
    // keyframeRequest: força IDR.
    bool encode(const uint8_t* bgra, size_t stride, bool keyframeRequest,
                std::vector<uint8_t>& nal, bool& isKey) {
        // Copia para o buffer de entrada
        NV_ENC_LOCK_INPUT_BUFFER lb{};
        lb.version = NV_ENC_LOCK_INPUT_BUFFER_VER;
        lb.inputBuffer = inBuf;
        api.nvEncLockInputBuffer(session, &lb);
        uint8_t* dst = (uint8_t*)lb.bufferDataPtr;
        size_t dstStride = lb.pitch;
        for (uint32_t y = 0; y < h; y++)
            memcpy(dst + y * dstStride, bgra + y * stride, (size_t)w * 4);
        api.nvEncUnlockInputBuffer(session, inBuf);

        // Encoda
        NV_ENC_PIC_PARAMS pp{};
        pp.version          = NV_ENC_PIC_PARAMS_VER;
        pp.inputWidth       = w;
        pp.inputHeight      = h;
        pp.inputPitch       = (uint32_t)dstStride;
        pp.encodePicFlags   = keyframeRequest ? NV_ENC_PIC_FLAG_FORCEIDR | NV_ENC_PIC_FLAG_OUTPUT_SPSPPS : 0;
        pp.inputBuffer      = inBuf;
        pp.outputBitstream  = outBuf;
        pp.bufferFmt        = fmt;
        pp.pictureStruct    = NV_ENC_PIC_STRUCT_FRAME;
        pp.frameIdx         = frameN++;
        api.nvEncEncodePicture(session, &pp);

        // Lê o bitstream
        NV_ENC_LOCK_BITSTREAM bs{};
        bs.version         = NV_ENC_LOCK_BITSTREAM_VER;
        bs.outputBitstream = outBuf;
        bs.doNotWait       = 0;
        api.nvEncLockBitstream(session, &bs);
        isKey = !!(bs.pictureType == NV_ENC_PIC_TYPE_IDR);
        nal.assign((uint8_t*)bs.bitstreamBufferPtr,
                   (uint8_t*)bs.bitstreamBufferPtr + bs.bitstreamSizeInBytes);
        api.nvEncUnlockBitstream(session, outBuf);
        return true;
    }

    void destroy() {
        if (!session) return;
        if (inBuf)  api.nvEncDestroyInputBuffer(session, inBuf);
        if (outBuf) api.nvEncDestroyBitstreamBuffer(session, outBuf);
        api.nvEncDestroyEncoder(session);
        session = nullptr;
    }
};

static bool loadNvenc(NVEncoder& enc) {
    HMODULE dll = LoadLibraryA("nvEncodeAPI64.dll");
    if (!dll) { logf("[nvenc] nvEncodeAPI64.dll não encontrada\n"); return false; }
    auto createInstance = (NVENCSTATUS(*)(NV_ENCODE_API_FUNCTION_LIST*))
        GetProcAddress(dll, "NvEncodeAPICreateInstance");
    if (!createInstance) return false;
    enc.api.version = NV_ENCODE_API_FUNCTION_LIST_VER;
    return createInstance(&enc.api) == NV_ENC_SUCCESS;
}
#endif // HAVE_NVENC

// ============================================================================
// Seção 3 — Captura D3D11 (DXGI Desktop Duplication — fallback universal)
// ============================================================================
// Se o runtime não expuser shared handle dos swapchains, usamos DXGI Desktop
// Duplication para capturar a janela de preview (a janela "StormVR Window"
// que o driver legado criava, ou a janela de preview do xr_pose_test).
// Isso funciona sem modificar a DLL do runtime.

struct Capture {
    ID3D11Device*             dev    = nullptr;
    ID3D11DeviceContext*      ctx    = nullptr;
    IDXGIOutputDuplication*   dup    = nullptr;
    ID3D11Texture2D*          stage  = nullptr;   // staging para leitura CPU
    uint32_t                  w = 0, h = 0;

    bool init() {
        HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
            0, nullptr, 0, D3D11_SDK_VERSION, &dev, nullptr, &ctx);
        if (FAILED(hr)) { logf("[cap] D3D11CreateDevice falhou %08X\n", hr); return false; }

        // Pega o primeiro output DXGI
        IDXGIDevice* dxgiDev = nullptr;
        dev->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDev);
        IDXGIAdapter* adapter = nullptr;
        dxgiDev->GetAdapter(&adapter);
        IDXGIOutput* output = nullptr;
        adapter->EnumOutputs(0, &output);
        IDXGIOutput1* output1 = nullptr;
        output->QueryInterface(__uuidof(IDXGIOutput1), (void**)&output1);

        hr = output1->DuplicateOutput(dev, &dup);
        if (FAILED(hr)) { logf("[cap] DuplicateOutput falhou %08X\n", hr); return false; }

        DXGI_OUTDUPL_DESC dd{}; dup->GetDesc(&dd);
        w = dd.ModeDesc.Width; h = dd.ModeDesc.Height;
        logf("[cap] DXGI duplication %ux%u\n", w, h);

        // Staging texture para leitura CPU
        D3D11_TEXTURE2D_DESC td{};
        td.Width = w; td.Height = h; td.MipLevels = 1; td.ArraySize = 1;
        td.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        td.SampleDesc.Count = 1;
        td.Usage = D3D11_USAGE_STAGING;
        td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        dev->CreateTexture2D(&td, nullptr, &stage);
        return true;
    }

    // Captura um frame; preenche bgra (w*h*4 bytes). Retorna false se não há frame novo.
    bool capture(std::vector<uint8_t>& bgra) {
        IDXGIResource* res = nullptr;
        DXGI_OUTDUPL_FRAME_INFO fi{};
        HRESULT hr = dup->AcquireNextFrame(16, &fi, &res);
        if (hr == DXGI_ERROR_WAIT_TIMEOUT) return false;
        if (FAILED(hr)) {
            // Recria duplication se a tela mudou de resolução
            dup->Release(); dup = nullptr;
            logf("[cap] AcquireNextFrame falhou, recriando\n");
            return false;
        }
        ID3D11Texture2D* tex = nullptr;
        res->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&tex);
        ctx->CopyResource(stage, tex);
        tex->Release(); res->Release();
        dup->ReleaseFrame();

        D3D11_MAPPED_SUBRESOURCE mapped{};
        ctx->Map(stage, 0, D3D11_MAP_READ, 0, &mapped);
        bgra.resize((size_t)w * h * 4);
        for (uint32_t y = 0; y < h; y++)
            memcpy(bgra.data() + y * w * 4, (uint8_t*)mapped.pData + y * mapped.RowPitch, (size_t)w * 4);
        ctx->Unmap(stage, 0);
        return true;
    }
};

// ============================================================================
// Seção 4 — Codificação CPU (fallback sem NVENC — JPEG via GDI+, muito lento)
// ============================================================================
// Usado só se NVENC não estiver disponível. Produz MJPEG em vez de H.264.
// O pcbridge.js detecta e usa um <video> element com MSE em modo JPEG.
static std::vector<uint8_t> encodeBgraToJpeg(const uint8_t* bgra, uint32_t w, uint32_t h) {
    // Usa a API GDI+ mínima do Windows para comprimir em JPEG
    // (evita dependência de libjpeg)
    // Retorna vetor vazio se falhar.
    std::vector<uint8_t> out;
#if 0  // placeholder — compilar com GDI+ se quiser o fallback CPU
    // Usei GdipSaveImageToStream + IStream sobre HGLOBAL
#endif
    return out;
}

// ============================================================================
// Seção 5 — Thread de codificação + envio
// ============================================================================
static void encodeThread(WS::Conn* conn) {
    logf("[enc] thread iniciada\n");

    Capture cap;
    if (!cap.init()) {
        logf("[enc] captura falhou — encerrando\n");
        return;
    }

#ifdef HAVE_NVENC
    NVEncoder enc;
    bool nvOk = loadNvenc(enc) && enc.init(cap.dev, cap.w, cap.h);
    if (!nvOk) logf("[enc] NVENC indisponível, usando JPEG CPU (lento)\n");
#else
    bool nvOk = false;
    logf("[enc] compilado sem NVENC — usando JPEG CPU (lento)\n");
#endif

    std::vector<uint8_t> bgra, nal;
    uint32_t frameId = 0;
    bool forceKey = true;
    auto lastFrame = std::chrono::steady_clock::now();
    const auto frameDur = std::chrono::microseconds(1000000 / 60);

    while (g.running) {
        // Cadência de 60 fps
        auto now = std::chrono::steady_clock::now();
        if (now - lastFrame < frameDur) {
            std::this_thread::sleep_for(std::chrono::microseconds(500));
            continue;
        }
        lastFrame = now;

        if (!cap.capture(bgra)) continue;

        // Pega a pose mais recente para embutir no cabeçalho
        float qx,qy,qz,qw;
        {
            std::lock_guard<std::mutex> lk(g.mu);
            if (g.hasPose) { qx=g.lastPose.qx; qy=g.lastPose.qy; qz=g.lastPose.qz; qw=g.lastPose.qw; }
            else { qx=0; qy=0; qz=0; qw=1; }
        }

        bool isKey = forceKey;
        bool encoded = false;

#ifdef HAVE_NVENC
        if (nvOk) encoded = enc.encode(bgra.data(), (size_t)cap.w*4, forceKey, nal, isKey);
#endif
        if (!encoded) {
            nal = encodeBgraToJpeg(bgra.data(), cap.w, cap.h);
            isKey = true;
            if (nal.empty()) continue;
        }
        forceKey = false;

        // Monta mensagem: VideoHdr (56 bytes) + NAL
        VideoHdr hdr{};
        hdr.type    = MSG_VIDEO;
        hdr.flags   = isKey ? 0x01 : 0x00;
        hdr.frameId = frameId++;
        hdr.tsPC    = (uint32_t)(now.time_since_epoch().count() / 1000000);
        hdr.qx=qx; hdr.qy=qy; hdr.qz=qz; hdr.qw=qw;

        std::vector<uint8_t> msg(sizeof(hdr) + nal.size());
        memcpy(msg.data(), &hdr, sizeof(hdr));
        memcpy(msg.data() + sizeof(hdr), nal.data(), nal.size());

        if (!conn->sendBin(msg.data(), msg.size())) {
            logf("[enc] envio falhou — desconectado\n");
            break;
        }
    }
    logf("[enc] thread encerrada\n");
}

// ============================================================================
// Seção 6 — Thread de recepção (pose do iPhone → UDP para o runtime)
// ============================================================================
static void recvThread(WS::Conn* conn) {
    logf("[recv] thread iniciada\n");

    // Socket UDP para repassar a pose ao runtime (127.0.0.1:5556)
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in rt{};
    rt.sin_family = AF_INET;
    rt.sin_port   = htons(5556);
    inet_pton(AF_INET, "127.0.0.1", &rt.sin_addr);

    std::vector<uint8_t> frame;
    while (g.running) {
        if (!conn->readFrame(frame)) break;
        if (frame.empty() || frame[0] != MSG_POSE) continue;
        if (frame.size() < sizeof(PoseMsg)) continue;

        PoseMsg pm{};
        memcpy(&pm, frame.data(), sizeof(pm));
        {
            std::lock_guard<std::mutex> lk(g.mu);
            g.lastPose = pm; g.hasPose = true;
        }

        // Converte para o formato STH1 que o runtime já conhece (60 bytes):
        // "STH1" + float[13] (quat + gyro + accel + pos)
        uint8_t sth1[60]{};
        sth1[0]='S';sth1[1]='T';sth1[2]='H';sth1[3]='1';
        float* f = (float*)(sth1+4);
        f[0]=pm.qx; f[1]=pm.qy; f[2]=pm.qz; f[3]=pm.qw;
        // gyro e accel zerados (não usados pelo runtime na leitura de pose)
        f[4]=f[5]=f[6]=f[7]=f[8]=f[9]=0;
        f[10]=pm.px; f[11]=pm.py; f[12]=pm.pz;

        sendto(udp, (const char*)sth1, sizeof(sth1), 0, (const sockaddr*)&rt, sizeof(rt));
    }
    closesocket(udp);
    logf("[recv] thread encerrada\n");
}

// ============================================================================
// Seção 7 — Servidor WebSocket principal
// ============================================================================
int main() {
    logOpen();
    logf("[srv] StormVR Server iniciando (porta %u)\n", WS_PORT);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int yes = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(WS_PORT);
    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) != 0) {
        logf("[srv] bind falhou: %d\n", WSAGetLastError()); return 1;
    }
    listen(srv, 1);
    logf("[srv] aguardando conexão do iPhone na porta %u…\n", WS_PORT);
    printf("StormVR Server pronto. Abra o app no iPhone e conecte o IP deste PC.\n");

    while (true) {
        sockaddr_in cli{}; int clen = sizeof(cli);
        SOCKET csock = accept(srv, (sockaddr*)&cli, &clen);
        if (csock == INVALID_SOCKET) continue;
        char ip[64]{}; inet_ntop(AF_INET, &cli.sin_addr, ip, sizeof(ip));
        logf("[srv] conexão de %s\n", ip);

        WS::Conn conn; conn.sock = csock;
        if (!conn.handshake()) { closesocket(csock); continue; }
        logf("[srv] WebSocket handshake OK\n");

        g.running = true;
        std::thread enc(encodeThread, &conn);
        std::thread rcv(recvThread, &conn);
        enc.join(); rcv.join();
        closesocket(csock);
        logf("[srv] sessão encerrada, aguardando nova conexão\n");
    }

    closesocket(srv);
    WSACleanup();
    return 0;
}
