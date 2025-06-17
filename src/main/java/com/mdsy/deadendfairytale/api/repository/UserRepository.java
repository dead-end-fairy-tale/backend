package com.mdsy.deadendfairytale.api.repository;

import com.mdsy.deadendfairytale.api.model.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, String> {

}
