package com.idat.ec2.dto;

public class ClienteRequestDTO {

	private Integer idClienteRequest;
	private String nombreCliente;
	private String direccionCliente;
	private Integer dniCliente;
	
	public Integer getIdClienteRequest() {
		return idClienteRequest;
	}
	public void setIdClienteRequest(Integer idClienteRequest) {
		this.idClienteRequest = idClienteRequest;
	}
	public String getNombreCliente() {
		return nombreCliente;
	}
	public void setNombreCliente(String nombreCliente) {
		this.nombreCliente = nombreCliente;
	}
	public String getDireccionCliente() {
		return direccionCliente;
	}
	public void setDireccionCliente(String direccionCliente) {
		this.direccionCliente = direccionCliente;
	}
	public Integer getDniCliente() {
		return dniCliente;
	}
	public void setDniCliente(Integer dniCliente) {
		this.dniCliente = dniCliente;
	}
	
	
}
