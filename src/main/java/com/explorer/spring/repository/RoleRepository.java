package com.explorer.spring.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.explorer.spring.models.EmployeeRole;
import com.explorer.spring.models.Role;

/**
 * Repository interface for accessing Role entities in the MongoDB database.
 * It extends MongoRepository, providing CRUD operations for Role objects.
 */
public interface RoleRepository extends MongoRepository<Role, String> {
  Optional<Role> findByName(EmployeeRole name);
}
