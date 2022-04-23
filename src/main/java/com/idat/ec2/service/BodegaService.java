package com.idat.ec2.service;

import java.util.List;

import com.idat.ec2.dto.BodegaRequestDTO;
import com.idat.ec2.dto.BodegaResponseDTO;

public interface BodegaService {

	public void guardarBodega(BodegaRequestDTO b);
	public void eliminarBodega(Integer id);
	public void editarBodega(BodegaRequestDTO b);
	public List<BodegaResponseDTO> listarBodegas();
	public BodegaResponseDTO findById(Integer id);
}
