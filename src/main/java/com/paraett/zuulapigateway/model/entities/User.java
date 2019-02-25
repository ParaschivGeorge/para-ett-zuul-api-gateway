package com.paraett.zuulapigateway.model.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.paraett.zuulapigateway.model.enums.UserType;

import javax.persistence.*;
import java.util.Date;
import java.util.List;

@Entity
@Table(name = "user_tbl")
public class  User {

    @Id
    @Column(name = "user_id")
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false, length = 100)
    private String username;

    @Column(unique = true, nullable = false, length = 50)
    private String email;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private UserType type;

    @JsonIgnore
    @Column(nullable = false)
    private boolean enabled;

    @JsonIgnore
    @Column(nullable = false)
    private String password;

    @JsonIgnore
    @Temporal(TemporalType.TIMESTAMP)
//    @NotNull
    private Date lastPasswordResetDate;

    @Column(name="last_login_date")
    private Date lastLoginDate;

    @JsonIgnore
    @Column(name="current_login_date")
    private Date currentLoginDate;

    @Column(name="manager_id")
    private Long managerId;

    @Column
    private Integer norm;

    @Column
    private Double salary;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public UserType getType() {
        return type;
    }

    public void setType(UserType type) {
        this.type = type;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Date getLastPasswordResetDate() {
        return lastPasswordResetDate;
    }

    public void setLastPasswordResetDate(Date lastPasswordResetDate) {
        this.lastPasswordResetDate = lastPasswordResetDate;
    }

    public Date getLastLoginDate() {
        return lastLoginDate;
    }

    public void setLastLoginDate(Date lastLoginDate) {
        this.lastLoginDate = lastLoginDate;
    }

    public Date getCurrentLoginDate() {
        return currentLoginDate;
    }

    public void setCurrentLoginDate(Date currentLoginDate) {
        this.currentLoginDate = currentLoginDate;
    }

    public Long getManagerId() {
        return managerId;
    }

    public void setManagerId(Long managerId) {
        this.managerId = managerId;
    }

    public Integer getNorm() {
        return norm;
    }

    public void setNorm(Integer norm) {
        this.norm = norm;
    }

    public Double getSalary() {
        return salary;
    }

    public void setSalary(Double salary) {
        this.salary = salary;
    }

    public User() {
    }

    public User(String username, String email, UserType type, boolean enabled, String password, Date lastPasswordResetDate, Date lastLoginDate, Date currentLoginDate, Long managerId, Integer norm, Double salary) {
        this.username = username;
        this.email = email;
        this.type = type;
        this.enabled = enabled;
        this.password = password;
        this.lastPasswordResetDate = lastPasswordResetDate;
        this.lastLoginDate = lastLoginDate;
        this.currentLoginDate = currentLoginDate;
        this.managerId = managerId;
        this.norm = norm;
        this.salary = salary;
    }
}