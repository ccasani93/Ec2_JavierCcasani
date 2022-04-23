package com.idat.ec2.service;

import java.util.List;

import com.idat.ec2.dto.ProductoRequestDTO;
import com.idat.ec2.dto.ProductoResponseDTO;

public interface ProductoService {

	
	public void guardarProducto(ProductoRequestDTO p);
	public void eliminarProducto(Integer id);
	public void editarProducto(ProductoRequestDTO p);
	public List<ProductoResponseDTO> listaProductos();
	public ProductoResponseDTO findById(Integer id);
	
	
}
