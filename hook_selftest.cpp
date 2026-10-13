#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <algorithm>
#include "engine_contract.h"

static bool Hash(const std::vector<uint8_t>& bytes,char out[65]) {
  HCRYPTPROV p=0; HCRYPTHASH h=0; BYTE digest[32]; DWORD n=32;
  bool ok=CryptAcquireContextW(&p,nullptr,nullptr,PROV_RSA_AES,CRYPT_VERIFYCONTEXT) &&
    CryptCreateHash(p,CALG_SHA_256,0,0,&h) && CryptHashData(h,bytes.data(),(DWORD)bytes.size(),0) &&
    CryptGetHashParam(h,HP_HASHVAL,digest,&n,0) && n==32;
  if(ok) { for(unsigned i=0;i<32;++i) sprintf(out+i*2,"%02x",digest[i]);out[64]=0; }
  if(h)CryptDestroyHash(h);if(p)CryptReleaseContext(p,0);return ok;
}
struct Probe { uint32_t width=0,height=0,next=0,commits=0,sizes=0; bool pending=false,valid=true; std::vector<uint8_t> bytes; };
static void __cdecl Size(void* data,uint32_t w,uint32_t h) {
  auto p=(Probe*)data; if(++p->sizes!=1 || !w || !h)p->valid=false;
  p->width=w;p->height=h;p->bytes.assign((size_t)w*h*4,0);
}
static void* __cdecl Row(void* data,int32_t y) {
  auto p=(Probe*)data;
  if(y==-1) { if(!p->pending)p->valid=false;p->pending=false;++p->commits;return nullptr; }
  if(p->sizes!=1 || p->pending || y<0 || (uint32_t)y!=p->next || (uint32_t)y>=p->height) { p->valid=false;return nullptr; }
  p->pending=true;++p->next;return p->bytes.data()+(size_t)y*p->width*4;
}
struct Stream { void** table; const std::vector<uint8_t>* bytes; uint64_t pos=0; uint32_t reads=0; };
static uint64_t __cdecl Seek(void* data,int64_t offset,int32_t origin) {
  auto s=(Stream*)data; int64_t base=origin==0 ? 0 : origin==1 ? (int64_t)s->pos : (int64_t)s->bytes->size();
  if(offset < -base || offset > (int64_t)s->bytes->size()-base)return UINT64_MAX;
  s->pos=(uint64_t)(base+offset);return s->pos;
}
static uint32_t __cdecl Read(void* data,void* dst,uint32_t count) {
  auto s=(Stream*)data;++s->reads;
  size_t n=std::min<size_t>(std::min<size_t>(count,37),s->bytes->size()-s->pos);
  memcpy(dst,s->bytes->data()+s->pos,n);s->pos+=n;return (uint32_t)n;
}
using DllProbe=int (__cdecl *)(void*,void*,SizeCallback,ScanlineCallback);
using DllVersion=unsigned (__cdecl *)();
int wmain(int argc,wchar_t** argv) {
  if(argc==2 && !wcscmp(argv[1],L"--version")) {
    unsigned v=JxlDecoderVersion();printf("{\"decoder_version\":%u,\"version\":\"%u.%u.%u\"}\n",v,v/1000000,(v/1000)%1000,v%1000);return 0;
  }
  if(argc!=6 || wcscmp(argv[1],L"--bgra") || wcscmp(argv[4],L"--hook")) {
    fwprintf(stderr,L"usage: hook_selftest --bgra input.jxl output.bgra --hook hook.dll\n");return 2;
  }
  HANDLE f=CreateFileW(argv[2],GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
  if(f==INVALID_HANDLE_VALUE)return 3;
  LARGE_INTEGER length; std::vector<uint8_t> input; DWORD got;
  bool ok=GetFileSizeEx(f,&length) && length.QuadPart>0 && length.QuadPart<=512LL*1024*1024;
  if(ok) { input.resize((size_t)length.QuadPart);ok=ReadFile(f,input.data(),(DWORD)input.size(),&got,nullptr) && got==input.size(); }
  CloseHandle(f);if(!ok)return 3;
  HMODULE dll=LoadLibraryW(argv[5]); if(!dll)return 4;
  auto probe=(DllProbe)GetProcAddress(dll,"IslandJxlProbe");auto version=(DllVersion)GetProcAddress(dll,"IslandJxlDecoderVersion");
  if(!probe || !version || version()!=JxlDecoderVersion())return 5;
  auto link=(HRESULT (__stdcall *)(void*))GetProcAddress(dll,"V2Link");
  auto unlink=(HRESULT (__stdcall *)())GetProcAddress(dll,"V2Unlink");
  // This synthetic executable is intentionally not the supported game.
  if(!link || !unlink || SUCCEEDED(link(nullptr)) || FAILED(unlink()))return 12;
  void* table[]={(void*)Seek,(void*)Read};Stream stream{table,&input};
  Probe callbacks;
  if(!probe(&stream,&callbacks,Size,Row) || stream.pos!=0 || !callbacks.valid || callbacks.pending ||
     callbacks.sizes!=1 || callbacks.next!=callbacks.height || callbacks.commits!=callbacks.height)return 6;
  JxlDecodedImage independent;
  if(!DecodeJxlToBgra(input.data(),input.size(),&independent) || independent.bgra!=callbacks.bytes)return 7;
  // Normal PNG magic must follow the fallback without consuming the stream or invoking callbacks.
  std::vector<uint8_t> png={0x89,0x50,0x4e,0x47,13,10,26,10,0,0,0,0};Stream pngStream{table,&png};Probe ignored;
  if(probe(&pngStream,&ignored,Size,Row)!=0 || pngStream.pos!=0 || ignored.sizes!=0)return 8;
  // Reject invalid data without callbacks; exercise restoration with short reads.
  std::vector<uint8_t> invalid={0xff,0x0a,0,0};Stream bad{table,&invalid};Probe rejected;
  if(probe(&bad,&rejected,Size,Row)!=0 || bad.pos!=0 || rejected.sizes!=0)return 9;
  char payloadHash[65],callbackHash[65];if(!Hash(input,payloadHash) || !Hash(callbacks.bytes,callbackHash))return 10;
  f=CreateFileW(argv[3],GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,0,nullptr);
  if(f==INVALID_HANDLE_VALUE)return 11;
  DWORD written;ok=WriteFile(f,callbacks.bytes.data(),(DWORD)callbacks.bytes.size(),&written,nullptr) && written==callbacks.bytes.size();
  CloseHandle(f);if(!ok)return 11;
  unsigned v=version();
  printf("{\"width\":%u,\"height\":%u,\"payload_sha256\":\"%s\",\"callback_sha256\":\"%s\",\"decoder_version\":%u,\"version\":\"%u.%u.%u\",\"callbacks\":true,\"commits\":%u,\"dll_handler\":true,\"png_fallback\":true,\"stream_restored\":true}\n",
    callbacks.width,callbacks.height,payloadHash,callbackHash,v,v/1000000,(v/1000)%1000,v%1000,callbacks.commits);
  FreeLibrary(dll);return 0;
}
