package com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@NoArgsConstructor
@ToString
@EqualsAndHashCode
@Getter
@Setter
@Document(collection = "roles")
public class Role {

    @Id
    private String id;

    private ERole name;

    public Role(ERole name) {
        this.name=name;
    }

}
