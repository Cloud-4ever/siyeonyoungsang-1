# ShopEasy API Server (Spring Boot)

## 설치 및 실행

```bash
# Maven Wrapper로 빌드 및 실행 (별도 설치 불필요)
./mvnw spring-boot:run

# 또는 JAR 빌드 후 실행
./mvnw clean package -DskipTests
java -jar target/api-server-spring-1.0.0.jar
```

서버 시작 시 데이터가 없으면 테스트 사용자 1명과 상품 20개가 자동으로 삽입됩니다.

AWS 모드로 실행하려면:

```bash
# 운영 설정 파일 생성
cp src/main/resources/application-prod.yml.example src/main/resources/application-prod.yml
# application-prod.yml에 AWS 정보 입력 후 실행
./mvnw spring-boot:run -Dspring-boot.run.profiles=prod
```

## 테스트 계정

| 항목 | 값 |
|------|-----|
| 이메일 | test@test.com |
| 비밀번호 | password123 |

## 환경변수 설명

Spring Boot는 `application.yml` + 프로파일 기반 설정 파일을 사용합니다.

### application.yml (공통)

| 속성 | 기본값 | 설명 |
|------|--------|------|
| `server.port` | `8080` | 서버 포트 번호 |
| `app.jwt.secret` | `ecommerce-jwt-secret-key-2024` | JWT 서명 비밀키 |

### application-local.yml (로컬 프로파일, 기본)

| 속성 | 값 | 설명 |
|------|------|------|
| `spring.datasource.url` | `jdbc:h2:file:./data/ecommerce;MODE=MySQL` | H2 파일 DB |
| `app.db.type` | `h2` | DB 종류 |
| `app.storage.type` | `local` | 로컬 파일 저장소 |
| `app.review.store` | `local` | DB 기반 리뷰 저장 |
| `app.cache.type` | `memory` | 인메모리 캐시 |
| `app.queue.type` | `sync` | 동기 큐 |

### application-prod.yml (운영 프로파일)

| 속성 | 예시 | 설명 |
|------|------|------|
| `spring.datasource.url` | `jdbc:mysql://rds-endpoint:3306/ecommerce` | MySQL RDS |
| `spring.datasource.username` | `admin` | DB 사용자 |
| `spring.datasource.password` | `your-password` | DB 비밀번호 |
| `app.storage.type` | `s3` | S3 파일 저장소 |
| `app.storage.s3.bucket` | `my-bucket` | S3 버킷 이름 |
| `app.storage.s3.region` | `ap-northeast-2` | S3 리전 |
| `app.review.store` | `dynamodb` | DynamoDB 리뷰 저장 |
| `app.review.dynamodb.table` | `Reviews` | DynamoDB 테이블 이름 |
| `app.review.dynamodb.region` | `ap-northeast-2` | DynamoDB 리전 |
| `app.cache.type` | `redis` | ElastiCache Redis |
| `spring.data.redis.host` | `redis-endpoint` | Redis 호스트 |
| `spring.data.redis.port` | `6379` | Redis 포트 |
| `app.queue.type` | `sqs` | SQS 메시지 큐 |
| `app.queue.sqs.queue-url` | `https://sqs...` | SQS 큐 URL |
| `app.queue.sns.topic-arn` | `arn:aws:sns:...` | SNS 토픽 ARN |

## API 엔드포인트

인증이 필요한 API는 `Authorization: Bearer <JWT토큰>` 헤더를 포함해야 합니다.

### 인증 (Auth)

| Method | Path | Auth | 설명 |
|--------|------|:----:|------|
| POST | `/api/auth/signup` | - | 회원가입 |
| POST | `/api/auth/login` | - | 로그인 |
| GET | `/api/auth/me` | O | 현재 사용자 정보 조회 |

### 상품 (Products)

| Method | Path | Auth | 설명 |
|--------|------|:----:|------|
| GET | `/api/products` | - | 상품 목록 조회 |
| GET | `/api/products/{id}` | - | 상품 상세 조회 |

### 리뷰 (Reviews)

| Method | Path | Auth | 설명 |
|--------|------|:----:|------|
| GET | `/api/products/{productId}/reviews` | - | 상품 리뷰 목록 조회 |
| POST | `/api/products/{productId}/reviews` | O | 리뷰 작성 |

### 장바구니 (Cart)

| Method | Path | Auth | 설명 |
|--------|------|:----:|------|
| GET | `/api/cart` | O | 장바구니 조회 |
| POST | `/api/cart` | O | 장바구니에 상품 추가 |
| PUT | `/api/cart/{itemId}` | O | 장바구니 수량 변경 |
| DELETE | `/api/cart/{itemId}` | O | 장바구니 항목 삭제 |
| DELETE | `/api/cart` | O | 장바구니 전체 삭제 |

### 주문 (Orders)

| Method | Path | Auth | 설명 |
|--------|------|:----:|------|
| POST | `/api/orders` | O | 주문 생성 |
| GET | `/api/orders` | O | 주문 내역 조회 |

### 파일 업로드 (Upload)

| Method | Path | Auth | 설명 |
|--------|------|:----:|------|
| POST | `/api/upload` | O | 이미지 파일 업로드 (최대 5MB) |
| POST | `/api/upload/presigned` | O | S3 Presigned URL 생성 |

### 시스템 (Health)

| Method | Path | Auth | 설명 |
|--------|------|:----:|------|
| GET | `/api/health` | - | 서버 상태 확인 |
| GET | `/api/config` | - | 현재 서비스 설정 조회 |
