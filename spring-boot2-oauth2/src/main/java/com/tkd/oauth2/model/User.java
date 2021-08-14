package com.tkd.oauth2.model;

import com.tkd.oauth2.enums.AuthProvider;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import javax.validation.constraints.NotNull;

@Entity
@Table(schema = "OAuth2Login", name = "[User]", uniqueConstraints = {
        @UniqueConstraint(columnNames = "Email")
})
@Getter
@Setter
public class User {
    @Id
    @GeneratedValue
    @Column(name = "Id")
    private Long id;

    @Column(name = "Name")
    private String name;

    @Column(name = "Email")
    private String email;

    @Column(name = "EmailVerified")
    private Boolean emailVerfied;

    @Column(name = "Password")
    private String password;

    @Column(name = "ImageUrl")
    private String imageUrl;

    @NotNull
    @Column(name = "AuthProvider")
    @Enumerated(EnumType.STRING)
    private AuthProvider authProvider;

    @Column(name = "ProviderId")
    private String providerId;
}
