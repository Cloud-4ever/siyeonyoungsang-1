# ShopEasy Frontend (React)

## 설치 및 실행

```bash
# 의존성 설치
npm install

# 개발 서버 실행 (http://localhost:3000)
npm run dev

# 프로덕션 빌드
npm run build
```

## API 서버 변경

`vite.config.js`의 proxy target 포트를 API 서버에 맞게 변경합니다.

### Node.js (Express) - 포트 5000

```js
proxy: {
  '/api': {
    target: 'http://localhost:5000',
    changeOrigin: true,
  },
  '/uploads': {
    target: 'http://localhost:5000',
    changeOrigin: true,
  },
},
```

### FastAPI - 포트 8000

```js
proxy: {
  '/api': {
    target: 'http://localhost:8000',
    changeOrigin: true,
  },
  '/uploads': {
    target: 'http://localhost:8000',
    changeOrigin: true,
  },
},
```

### Spring Boot - 포트 8080

```js
proxy: {
  '/api': {
    target: 'http://localhost:8080',
    changeOrigin: true,
  },
  '/uploads': {
    target: 'http://localhost:8080',
    changeOrigin: true,
  },
},
```

## S3 정적 호스팅 배포

S3에 배포할 때는 Vite의 proxy가 동작하지 않으므로, API 서버의 실제 주소를 환경변수로 지정한 뒤 빌드해야 합니다.

### 1. 환경변수 설정

API 서버는 ECS/EKS에 배포되며 앞단에 로드밸런서(ALB)가 위치합니다. 프로젝트 루트에 `.env.production` 파일을 생성하고 로드밸런서 DNS를 설정합니다.

```env
VITE_API_URL=http://<ALB-DNS-이름>
```

예시:

```env
VITE_API_URL=http://my-alb-123456789.ap-northeast-2.elb.amazonaws.com
```

### 2. 빌드 및 업로드

```bash
# 빌드 (dist/ 폴더 생성)
npm run build

# S3에 업로드
aws s3 sync dist/ s3://<버킷이름> --delete
```

### 3. S3 버킷 설정

- 정적 웹 사이트 호스팅 활성화
- 인덱스 문서: `index.html`
- 오류 문서: `index.html` (SPA 라우팅을 위해 동일하게 설정)

## CloudFront 배포

HTTPS가 적용되므로, API 서버도 HTTPS로 동작하게 해야합니다. (무료 도메인 + 무료 인증서 적용하면 가능함.)

CloudFront를 사용하면 HTTPS 적용과 API 프록시 설정이 가능합니다.

### 1. 환경변수 설정

CloudFront에서 API 요청을 프록시하는 경우, 별도의 `VITE_API_URL` 설정이 필요 없습니다.

```env
# CloudFront가 API를 프록시하는 경우 (비워두거나 파일 생성하지 않음)
VITE_API_URL=
```

CloudFront 프록시를 사용하지 않는 경우, S3 배포와 동일하게 ALB DNS를 설정합니다.

```env
VITE_API_URL=http://<ALB-DNS-이름>
```

### 2. 빌드 및 업로드

```bash
npm run build
aws s3 sync dist/ s3://<버킷이름> --delete
```

### 3. CloudFront 오리진 설정

| 오리진 | 도메인 | 용도 |
|--------|--------|------|
| S3 오리진 | `<버킷이름>.s3.amazonaws.com` | 프론트엔드 정적 파일 |
| API 오리진 (선택) | `<ALB-DNS-이름>` | API 프록시 (ECS/EKS 앞단의 ALB) |

### 4. CloudFront 동작(Behavior) 설정

| 경로 패턴 | 오리진 | 설명 |
|-----------|--------|------|
| `/api/*` | API 오리진 | API 요청을 백엔드로 전달 |
| `/uploads/*` | API 오리진 | 업로드 파일 요청을 백엔드로 전달 |
| `*` (기본) | S3 오리진 | 프론트엔드 정적 파일 |

### 5. CloudFront 오류 페이지 설정

SPA 라우팅을 위해 오류 페이지를 설정합니다.

| HTTP 오류 코드 | 응답 페이지 경로 | HTTP 응답 코드 |
|---------------|-----------------|---------------|
| 403 | `/index.html` | 200 |
| 404 | `/index.html` | 200 |
