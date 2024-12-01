package com.ead.authuser.services.impl;

import com.ead.authuser.repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class RoleServiceimpl {

    @Autowired
    RoleRepository roleRepository;
}
