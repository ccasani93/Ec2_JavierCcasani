package com.idat.ec2.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import com.idat.ec2.dto.ProductoRequestDTO;
import com.idat.ec2.dto.ProductoResponseDTO;
import com.idat.ec2.model.Productos;
import com.idat.ec2.repository.ProductoRepository;

public class ProducrtoServiceImpl implements ProductoService {

	
	@Autowired
	private ProductoRepository repository;
	
	@Override
	public void guardarProducto(ProductoRequestDTO p) {
		// TODO Auto-generated method stub
		
		Productos productos = new Productos();
		productos.setIdProducto(p.getIdProductoRequest());
		productos.setProducto(p.getNombreProducto());
		productos.setDescripcion(p.getDescripcion());
		productos.setPrecio(p.getPrecioProducto());
		productos.setStock(p.getStockProducto());
		repository.save(productos);
	}

	@Override
	public void eliminarProducto(Integer id) {
		// TODO Auto-generated method stub
		repository.deleteById(id);
	}

	@Override
	public void editarProducto(ProductoRequestDTO p) {
		// TODO Auto-generated method stub
		Productos productos = new Productos();
		productos.setIdProducto(p.getIdProductoRequest());
		productos.setProducto(p.getNombreProducto());
		productos.setDescripcion(p.getDescripcion());
		productos.setPrecio(p.getPrecioProducto());
		productos.setStock(p.getStockProducto());
		repository.saveAndFlush(productos);
		
	}

	@Override
	public List<ProductoResponseDTO> listaProductos() {
		// TODO Auto-generated method stub
		
		List<Productos> producto = repository.findAll();
		List<ProductoResponseDTO> dto = new ArrayList<ProductoResponseDTO>();
		ProductoResponseDTO productoDTO = null;
		
		for (Productos productos : producto) {
			productoDTO = new ProductoResponseDTO();
			productoDTO.setIdProductoResponse(productos.getIdProducto());
			productoDTO.setNombreProducto(productos.getProducto());
			productoDTO.setDescripcion(productos.getDescripcion());			
			productoDTO.setPrecioProducto(productos.getPrecio());
			productos.setStock(productos.getStock());
			
		}
		return dto;
	}

	@Override
	public ProductoResponseDTO findById(Integer id) {
		// TODO Auto-generated method stub
		
		Productos productos = repository.findById(id).orElse(null);
		ProductoResponseDTO productoDTO = new ProductoResponseDTO();
		
		productoDTO = new ProductoResponseDTO();
		productoDTO.setIdProductoResponse(productos.getIdProducto());
		productoDTO.setNombreProducto(productos.getProducto());
		productoDTO.setDescripcion(productos.getDescripcion());			
		productoDTO.setPrecioProducto(productos.getPrecio());
		productos.setStock(productos.getStock());
		
		return productoDTO;
	}

}
