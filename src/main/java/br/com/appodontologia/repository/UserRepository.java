package br.com.appodontologia.repository;

import br.com.appodontologia.domain.entity.Users;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends MongoRepository<Users, String> {
    Boolean existsByEmail(String email);
    Optional<Users> findByEmail(String email);
}
