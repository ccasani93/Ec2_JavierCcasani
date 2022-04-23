package com.idat.ec2.dto;

public class ProductoResponseDTO {

	
	private Integer idProductoResponse;
	private String nombreProducto;
	private String descripcion;
	private Double precioProducto;
	private Integer stockProducto;
	
	
	public Integer getIdProductoResponse() {
		return idProductoResponse;
	}
	public void setIdProductoResponse(Integer idProductoResponse) {
		this.idProductoResponse = idProductoResponse;
	}
	public String getNombreProducto() {
		return nombreProducto;
	}
	public void setNombreProducto(String nombreProducto) {
		this.nombreProducto = nombreProducto;
	}
	public String getDescripcion() {
		return descripcion;
	}
	public void setDescripcion(String descripcion) {
		this.descripcion = descripcion;
	}
	public Double getPrecioProducto() {
		return precioProducto;
	}
	public void setPrecioProducto(Double precioProducto) {
		this.precioProducto = precioProducto;
	}
	public Integer getStockProducto() {
		return stockProducto;
	}
	public void setStockProducto(Integer stockProducto) {
		this.stockProducto = stockProducto;
	}
	
	
	
}
