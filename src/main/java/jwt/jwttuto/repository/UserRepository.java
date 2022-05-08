package jwt.jwttuto.repository;

import jwt.jwttuto.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    @EntityGraph(attributePaths = "authorities") // Eager로 같이 가져옴
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}