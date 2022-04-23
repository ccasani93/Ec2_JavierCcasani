package com.idat.ec2.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.idat.ec2.model.Usuario;
import com.idat.ec2.repository.UsuarioRepository;
public class JWTUserDetailService implements UserDetailsService {

	@Autowired
	private UsuarioRepository repository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		Usuario usuario = repository.findByUsuario(username);					
		
		if(usuario != null) {
			List<GrantedAuthority> granted = new ArrayList<GrantedAuthority>();
			GrantedAuthority autority = new SimpleGrantedAuthority(usuario.getRol());
			granted.add(autority);
			return new User(usuario.getUsuario(), new BCryptPasswordEncoder().encode(usuario.getPassword()), granted);
			
		}else {
			throw new UsernameNotFoundException("El usuario no existe");
		}
	}

}
