package kr.co.tj.apigatewayservice.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.google.common.net.HttpHeaders;

import io.jsonwebtoken.Jwts;
import lombok.Data;
import reactor.core.publisher.Mono;


//<-> @Bean: 개발자가 직접 컨트롤이 불가능한 외부 라이브러리를 Bean으로 등록할때, 메소드 또는 어노테이션 단위에 사용
@Component // 개발자가 직접 컨트롤 가능한 클래스 , 인터페이스에 사용
public class AuthorizationFilter extends AbstractGatewayFilterFactory<AuthorizationFilter.Config> {
	// 스프링 클라우드 게이트웨이에서 필터를 정의함
	
	//private static final String SECRETE_KEY = "aaaaaaaaaaaaaa";
	
	private Environment env; 
	//객체 Environment을 주입받기 위해 인스턴스변수 선언.
	// Environment? 현재 애플리케이션의 실행되는 환경-> 프로퍼티(.yaml) 접근하고 관리 할 수 있음.
	// environment.getProperty("db.url")와 같이 키를 전달하여 어플리케이션의 설정 정보값을 받아옴.
	
	
	@Autowired
	public AuthorizationFilter(Environment env) {//의존성 주입(객체생성과 초기화과정을 생략함)
		super(Config.class);
		this.env = env;
	}
	
	
	//생성자
	public AuthorizationFilter() {
		super(Config.class); //AbstractGatewayFilterFactory의 생성자 호출하고, Config.class가 필터에 적용
	}
	
	//@Data
	public static class Config{
		//private String role; //Config클래스의 admin 확인용 -> api의 .yml 파일을 확인.
		
	}

	@Override
	public GatewayFilter apply(Config config) { //GatewayFilter를 반환 필터의 동작을 정의	
		//System.out.println(config.role);

		return (exchange, chain) ->{
			ServerHttpRequest request = exchange.getRequest();
			
			if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) { //요청 헤더에 AUTHORIZATION(키)가 있는지 물음			
			return onError(exchange,"authorization 키가 없습니다.", HttpStatus.UNAUTHORIZED); //없으면 onError메서드 호출 UNAUTHORIZED 상태반환
			}
			
			String bearerToken = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0); // AUTHORIZATION(키)의 값을 불러옴.
			
			
			// 순수 토큰값만 받는 두가지 방식
			// 1.
			// String token = bearerToken.split(" ")[1]; 
			// 예를 들어 토큰값이 "Bearer abcdef123456"일경우 공백(split(" "))을 기준으로 [0]은Bearer, [1]은 abcdef123456 를 token 변수에 담음
			
			// 2.
			String token = bearerToken.replace("Bearer ","");
			// 토큰을 받으면 Bearer가 붙는데  "Bearer "을 빈칸으로하여 순수 토큰값만 받음.
			
			
			// 유효성 검사(isJwtValid)
		      if(!isJwtValid(token)) {
		          return onError(exchange, "토큰이 유효하지 않습니다.", HttpStatus.UNAUTHORIZED);         
		       }

			
			//-------  ^ 요청할때 필터
			return chain.filter(exchange);
		};
	}

	//토큰의 유효성 검사
	private boolean isJwtValid(String token) {
		boolean isValid = true;
		String subject = null;
		
		try {
			subject = Jwts.parser().setSigningKey(env.getProperty("data.SECRETE_KEY")) //.yaml 파일에 추가했던 시크릿키값 호출
			.parseClaimsJws(token).getBody().getSubject();
			
		} catch (Exception e) {
			e.printStackTrace();
			isValid = false; //유효성 검사 실패 = 유효하지 않다.

		}
		
		if(subject == null || subject.isEmpty()) {
			isValid = false;
			
		}
		
		return isValid;
	}

	private Mono<Void> onError(ServerWebExchange exchange, String string, HttpStatus status) {
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(status);
		//return response; //Type mismatch: cannot convert from ServerHttpResponse to Mono<Void>
		return response.setComplete();
	}
	

}
