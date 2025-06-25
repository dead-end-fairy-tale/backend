# 막장동화 백엔드 입니다 #

## API 목록 ##
API 목록은 swagger를 사용하여 나타냈습니다.  
로컬 사용 시 : http://localhost:8080/swagger-ui/index.html  
서버 주소 : http://3.38.247.17/swagger-ui/index.html

## 기능 명세서 ##
- /api
  - /auth : 로그인과 관련된 API 주소입니다.
    - /login [post] : 로그인 API
    - /signup [post] : 회원가입 API
    - /logout [get, post] : 로그아웃 API
    - /send-email-verification [post] : 이메일 인증 보내기 API
    - /verify-email [post] : 이메일 인증 확인 API
    - /token [post] : 액세스 토큰 갱신 API
    - /reset-password [put, patch] : 비밀번호 초기화 API
    - /change-password : [post] : 비밀번호 변경 API
   
## CICD 사이트 ##
http://3.38.166.14:8080  

CI/CD 도구는 젠킨스를 사용하였습니다.  

Github의 commit을 webhook을 사용하여 인식하고  
jenkins pipeline script를 사용하여 build test를 한 이후에  
SSH를 사용하여 backend EC2 서버에 접속하고  
8080포트를 사용중인지 검색한 이후 사용중이라면 kill 명령어를 이용하여 내린 후  
build된 jar파일을 복사하여 backend EC2에 불러와서  
nohup으로 백그라운드 실행을 합니다.
