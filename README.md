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
