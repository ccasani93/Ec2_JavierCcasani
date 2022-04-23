package com.idat.ec2.dto;

public class BodegaRequestDTO {

	private Integer idBodegaRequest;
	private String nombreBodega;
	private String direccionBodega;
	
	
	public Integer getIdBodegaRequest() {
		return idBodegaRequest;
	}
	public void setIdBodegaRequest(Integer idBodegaRequest) {
		this.idBodegaRequest = idBodegaRequest;
	}
	public String getNombreBodega() {
		return nombreBodega;
	}
	public void setNombreBodega(String nombreBodega) {
		this.nombreBodega = nombreBodega;
	}
	public String getDireccionBodega() {
		return direccionBodega;
	}
	public void setDireccionBodega(String direccionBodega) {
		this.direccionBodega = direccionBodega;
	}
	
}
