package seg3x02.tempconverterapi.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class WebSecurityConfig {

    @Bean
    @Throws(Exception::class)
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http.authorizeHttpRequests{auth -> auth
            .requestMatchers("/temperature-converter/**").hasAnyRole("USER", "ADMIN")
            .anyRequest().authenticated()
        }
            .httpBasic()
        return http.build();
    }

    @Bean
    fun users(): UserDetailsService {
        val user1 = User.builder()
            .username("user1")
            .password(passwordEncoder().encode("pass1"))
            .roles("USER")
            .build()
        val user2 = User.builder()
            .username("user2")
            .password(passwordEncoder().encode("pass2"))
            .roles("ADMIN")
            .build()

        return InMemoryUserDetailsManager(user1, user2);
    }

    @Bean
    fun passwordEncoder(): BCryptPasswordEncoder {
        return BCryptPasswordEncoder();
    }
}