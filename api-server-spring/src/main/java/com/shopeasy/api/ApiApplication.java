package com.shopeasy.api;

import com.shopeasy.api.service.DatabaseService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class ApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiApplication.class, args);
    }

    @Bean
    public CommandLineRunner seedData(DatabaseService databaseService) {
        return args -> {
            try {
                // Check if users table has data
                Integer count = databaseService.queryForObject(
                        "SELECT COUNT(*) FROM users", Integer.class
                );

                if (count != null && count > 0) {
                    System.out.println("Database already has data, skipping seed.");
                    return;
                }
            } catch (Exception e) {
                System.out.println("Error checking seed status: " + e.getMessage());
                return;
            }

            System.out.println("Seeding database...");

            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

            // Insert test user
            String hashedPassword = passwordEncoder.encode("password123");
            databaseService.update(
                    "INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)",
                    "test@test.com", hashedPassword, "테스트유저"
            );

            // Insert 20 products
            String[][] products = {
                    // Electronics (전자기기)
                    {"삼성 갤럭시 S24 울트라", "최신 AI 기능을 탑재한 프리미엄 스마트폰. 2억 화소 카메라와 티타늄 프레임으로 완성된 최고의 스마트폰입니다.", "1698000", "/images/products/product-1.jpg", "전자기기", "50"},
                    {"LG 그램 17인치 노트북", "초경량 17인치 노트북. 뛰어난 배터리 수명과 성능을 갖춘 업무용 노트북입니다.", "1890000", "/images/products/product-2.jpg", "전자기기", "30"},
                    {"애플 에어팟 프로 2세대", "능동형 소음 차단과 적응형 오디오를 지원하는 무선 이어폰입니다.", "359000", "/images/products/product-3.jpg", "전자기기", "100"},
                    {"LG 스탠바이미 27인치", "이동이 자유로운 무선 스탠드 모니터. 터치스크린과 배터리 내장으로 어디서든 사용 가능합니다.", "1090000", "/images/products/product-4.jpg", "전자기기", "20"},

                    // Fashion (패션)
                    {"나이키 에어맥스 97 화이트", "클래식한 디자인의 나이키 에어맥스. 풀 에어 유닛으로 편안한 착용감을 제공합니다.", "219000", "/images/products/product-5.jpg", "패션", "80"},
                    {"유니클로 히트텍 울트라 웜 세트", "한겨울에도 따뜻한 히트텍 울트라 웜 상하의 세트. 발열 기능이 뛰어납니다.", "49900", "/images/products/product-6.jpg", "패션", "200"},
                    {"캉골 버킷햇 클래식", "캉골의 시그니처 버킷햇. 사계절 착용 가능한 클래식 디자인입니다.", "69000", "/images/products/product-7.jpg", "패션", "150"},
                    {"노스페이스 눕시 패딩 자켓", "가볍고 따뜻한 눕시 패딩. 700 필파워 구스다운으로 보온성이 뛰어납니다.", "399000", "/images/products/product-8.jpg", "패션", "60"},

                    // Food (식품)
                    {"곰곰 유기농 현미 10kg", "국내산 유기농 현미. 건강한 식단을 위한 프리미엄 쌀입니다.", "42900", "/images/products/product-9.jpg", "식품", "300"},
                    {"정관장 홍삼정 에브리타임 30포", "6년근 홍삼 농축액을 담은 스틱형 건강기능식품입니다.", "52000", "/images/products/product-10.jpg", "식품", "500"},
                    {"비비고 왕교자 만두 1.4kg", "풍부한 속재료가 가득한 왕교자 만두. 간편하게 조리할 수 있습니다.", "12900", "/images/products/product-11.jpg", "식품", "1000"},
                    {"스타벅스 캡슐 커피 믹스 60개입", "스타벅스 원두를 사용한 캡슐 커피. 다양한 맛을 즐길 수 있습니다.", "34900", "/images/products/product-12.jpg", "식품", "400"},

                    // Home & Living (생활용품)
                    {"다이슨 V15 무선 청소기", "레이저 먼지 감지 기술이 탑재된 최신 무선 청소기입니다.", "1190000", "/images/products/product-13.jpg", "생활용품", "25"},
                    {"쿠쿠 IH 전기압력밥솥 10인용", "IH 가열 방식으로 맛있는 밥을 짓는 전기압력밥솥입니다.", "289000", "/images/products/product-14.jpg", "생활용품", "40"},
                    {"코웨이 아이콘 정수기 렌탈", "슬림한 디자인의 직수형 정수기. 냉온수 기능을 제공합니다.", "39900", "/images/products/product-15.jpg", "생활용품", "100"},
                    {"일룸 데스커 모션 데스크", "전동 높이 조절이 가능한 스탠딩 데스크. 인체공학적 설계입니다.", "699000", "/images/products/product-16.jpg", "생활용품", "15"},

                    // Beauty (뷰티)
                    {"설화수 자음생 크림 60ml", "인삼 성분이 함유된 프리미엄 안티에이징 크림입니다.", "170000", "/images/products/product-17.jpg", "뷰티", "70"},
                    {"이니스프리 그린티 세럼 80ml", "제주 녹차 성분으로 피부를 촉촉하게 가꿔주는 세럼입니다.", "25000", "/images/products/product-18.jpg", "뷰티", "300"},
                    {"라네즈 립 슬리핑 마스크 20g", "자는 동안 입술을 촉촉하게 케어하는 립 마스크입니다.", "18000", "/images/products/product-19.jpg", "뷰티", "500"},
                    {"에스티로더 더블웨어 파운데이션", "24시간 지속력의 풀커버 파운데이션. 다양한 피부톤에 맞는 색상을 제공합니다.", "64000", "/images/products/product-20.jpg", "뷰티", "120"}
            };

            for (String[] product : products) {
                databaseService.update(
                        "INSERT INTO products (name, description, price, image_url, category, stock) VALUES (?, ?, ?, ?, ?, ?)",
                        product[0], product[1], Integer.parseInt(product[2]), product[3], product[4], Integer.parseInt(product[5])
                );
            }

            System.out.println("Database seeded successfully with 1 user and 20 products.");
        };
    }
}
