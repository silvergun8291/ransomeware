import glob
import os, random, struct
from Cryptodome.Cipher import AES
import secrets
import hashlib
import getpass

class AES128():
    def GetKey(self):   # 저장된 AES Key를 얻어오는 함수
        fin = open('110011000100011101111000001.txt', 'rt')    # 읽기 모드로 파일 오픈
        key_str = fin.read()    # key_str에 파일 내용 저장
        Key = bytes(key_str, 'utf-8')   # Key 변수에 파일 내용을 Bytes형으로 변환하여 대입
        return Key  # Key 값을 리턴

    def decrypt_file(self, in_filename, key, out_filename=None, chunksize=24*1024):  # 파일 복호화 함수
        if not out_filename:
            out_filename = os.path.splitext(in_filename)[0] # 파일명이 지정되지 않을 경우, 기존파일의 확장자를 추출

        with open(in_filename, 'rb') as infile: # 현재 파일을 바이너리로 읽어들임
            origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0] # 현재 파일의 int형으로 된 부분을 읽어들여 다시 원래상태로 언패킹함 
            iv = infile.read(16) # 현재파일의 16자리를 읽어들임
            decryptor = AES.new(key, AES.MODE_CBC, iv) # AES로 암호화된 키값을 생성

            with open(out_filename, 'wb') as outfile: # 새 파일을 바이너리 모드로 생성
                while True:
                    chunk = infile.read(chunksize) # 쓰레기값을 읽어들임 65536
                    if len(chunk) == 0: # 쓰레기값이 0일 경우 루프 탈출
                        break
                    outfile.write(decryptor.decrypt(chunk)) # 쓰레기를 복호화해서 새파일에 작성

                outfile.truncate(origsize) # 새 파일에 언패킹한 크기 만큼 잘라냄

    def Decryption(self, key):   # 컴퓨터 내 암호화 된 .enc 파일을 복호화
        #Decrypts the files
        PathList = []   # 경로들을 저장할 리스트
        username = getpass.getuser()    # 컴퓨터 유저 이름을 username에 저장
        path = os.path.join(r"C:\Users", username, "Desktop\test\\**")   # C드라이브 경로를 path에 저장
        PathList.append(path)    # PathList에 C드라이브 경로 추가

        #Encrypts all files recursively starting from startPath
        for Path in PathList:
            for filename in glob.iglob(Path, recursive=True): # 대상 경로를 재귀적 호출 사용
                if(os.path.isfile(filename)): # 현재 파일이 파일일때
                    fname, ext = os.path.splitext(filename) # 파일명과 확장자를 추출
                    if (ext == '.enc'): # 확장자가 .enc (암호화된 파일일 때)
                        print('Decrypting> ' + filename) # 파일명 출력 (디버깅 용)
                        self.decrypt_file(filename, key) # 복호화 함수 실행
                        os.remove(filename) # 암호화됐던 파일을 제거


class RSA():
    def Decrypt(self, data, privateKey):    # 복호화 연산 함수
        n = 1052651  # 공개키1 (p x q)
        result = (data ** privateKey) % n   # 복호화 연산 수행
        result = chr(result)    # 복호화 결과를 아스키코드로 변환
        result = bytes(result, 'utf-8')    # bytes로 형변환
        return result   # 복호화 결과 반환

    def Decryption(self, privateKey, out_filename=None):    # 복호화 함수
            in_filename = '110011000100011101111000001.txt.enc'    # 암호화된 AES Key 파일 이름 대입
            if not out_filename:
                out_filename = os.path.splitext(in_filename)[0] # 파일명이 지정되지 않을 경우, 기존파일의 확장자를 추출
            
            with open(in_filename, 'rb') as infile:    # 암호화 된 AES Key 파일을 바이너리 읽기 모드로 오픈
                with open(out_filename, 'wb') as outfile:   # 복호화 결과를 쓸 파일을 바이너리 쓰기 모드로 오픈
                    data = infile.read()    # 암호화 된 AES Key 파일의 데이터를 읽어서 저장
                    data_str = str(data)    # data를 string로 형변환
                    data_str = data_str.replace('b', '')    # data에서 b문자 제거
                    data_str = data_str.replace("'", '')    # data에서 '문자 제거
                    data_list = data_str.split(" ") # data를 공백을 기준으로 리스트로 변환
                    data_list.pop()    # 리스트의 마지막 요소 삭제
                    for i in range(len(data_list)):
                        result = self.Decrypt(int(data_list[i]), privateKey)    # data 복호화 결과 result에 대입
                        outfile.write(result)   # 복호화된 데이터를 파일에 씀


#최종 복호화 함수
def Decryption():
    hash = "2aef2c75605e37237bdd5950062478d9eae127c076142aabfe8c2562c87d443d"   # private key의 해시값
    privateKey = input("복호화 키를 입력하세요: ")   # 최종 복호화 키
    hash_key = hashlib.sha256(privateKey.encode())  # 입력받은 복호화 키의 해시값을 구함
    result = hash_key.hexdigest()
    if hash == result:  # private key의 해시값과 입력받은 키의 해시값이 일치하면 복호화 수행
        rsa = RSA()
        aes = AES128()
        rsa.Decryption(int(privateKey))  # 입력받은 개인키로 AES Key 파일 복호화
        AES_Key = aes.GetKey()  # 복호화된 AES Key를 얻어옴
        aes.Decryption(AES_Key)    # 컴퓨터 파일 복호화
    else: # private key의 해시값과 입력받은 키의 해시값이 불일치하면 에러 메세지 출력
        print("잘못된 복호화키를 입력했습니다.")
        

Decryption()
