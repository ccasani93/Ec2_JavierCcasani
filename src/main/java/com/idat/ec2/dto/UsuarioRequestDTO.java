package com.idat.ec2.dto;

public class UsuarioRequestDTO {

	
	private String nombreUsuario;
	private String contrasenia;
	
	
	public UsuarioRequestDTO() {
		super();
	}
	public UsuarioRequestDTO(String usuario, String contrasenia) {
		super();
		this.nombreUsuario = usuario;
		this.contrasenia = contrasenia;
	}
	
	
	public String getNombreUsuario() {
		return nombreUsuario;
	}
	public void setNombreUsuario(String nombreUsuario) {
		this.nombreUsuario = nombreUsuario;
	}
	public String getContrasenia() {
		return contrasenia;
	}
	public void setContrasenia(String contrasenia) {
		this.contrasenia = contrasenia;
	}
	
	
	
}
