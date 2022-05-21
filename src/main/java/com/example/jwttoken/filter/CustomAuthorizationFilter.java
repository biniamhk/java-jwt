package com.example.jwttoken.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    //make all the filter for incoming request using the token
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")) {
            //if the path is login we do not need to check
            filterChain.doFilter(request, response);
        } else {
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            //if this is true,the user is a valid user
            if(authorizationHeader!=null && authorizationHeader.startsWith("Bearer ")){
                try{
                    //delete the bearer from header
                    String token=authorizationHeader.substring("Bearer ".length());
                    //should be the same with the algorithm that add to the token during creation,
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                    //verify the token using the algorithm
                    JWTVerifier verifier= JWT.require(algorithm).build();
                    //verify the token is valid
                    DecodedJWT decodedJWT=verifier.verify(token);
                    //get the username from the subject
                    String username=decodedJWT.getSubject();
                    //get the roles using the key we gave to the token during creation
                    String[] roles= decodedJWT.getClaim("roles").asArray(String.class);
                    //change the string role in to SimpleGrantedAuthority type because
                    // UsernamepasswordAuthenticationToken did not accept string value.
                    Collection<SimpleGrantedAuthority> authorities=new ArrayList<>();
                    stream(roles).forEach(role->{
                        authorities.add(new SimpleGrantedAuthority(role));
                    });
                    UsernamePasswordAuthenticationToken authenticationToken= new
                            UsernamePasswordAuthenticationToken(username,null,authorities);
                    //tell the spring security what a user can do or can access
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    //continue the process
                    filterChain.doFilter(request,response);

                }catch (Exception exception){
                    log.error("Error logging in:{}",exception.getMessage());
                    response.setHeader("error",exception.getMessage());
                    response.setStatus(FORBIDDEN.value());
                    //we can do the first or second choice
                    //response.sendError(FORBIDDEN.value());
                    Map<String, String> error = new HashMap<String, String>();
                    error.put("error_message",exception.getMessage());
                    //return Json tokens
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(),error);


                }
            }
            else
                filterChain.doFilter(request,response);
        }
    }
}
