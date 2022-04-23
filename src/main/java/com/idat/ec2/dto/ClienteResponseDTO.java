package com.idat.ec2.dto;

public class ClienteResponseDTO {

	private Integer idClienteResponse;
	private String nombreCliente;
	private String direccionCliente;
	private Integer dniCliente;
	
	
	public Integer getIdClienteResponse() {
		return idClienteResponse;
	}
	public void setIdClienteResponse(Integer idClienteResponse) {
		this.idClienteResponse = idClienteResponse;
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
