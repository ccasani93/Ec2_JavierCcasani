package com.idat.ec2.model;

import javax.persistence.Entity;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Table(name = "bodegas")
@Entity

public class Bodega {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer idBodega;
	private String nombre;
	private String direccion;
	
	
	@ManyToOne
	@JoinColumn(name = "id_producto", nullable = false, unique = true, foreignKey = @ForeignKey(foreignKeyDefinition = "foreign key (id_producto) references productos (id_producto)"))
	private Productos productos;


	public Integer getIdBodega() {
		return idBodega;
	}


	public void setIdBodega(Integer idBodega) {
		this.idBodega = idBodega;
	}


	public String getNombre() {
		return nombre;
	}


	public void setNombre(String nombre) {
		this.nombre = nombre;
	}


	public String getDireccion() {
		return direccion;
	}


	public void setDireccion(String direccion) {
		this.direccion = direccion;
	}


	public Productos getProductos() {
		return productos;
	}


	public void setProductos(Productos productos) {
		this.productos = productos;
	}
	
	
	
	
}
