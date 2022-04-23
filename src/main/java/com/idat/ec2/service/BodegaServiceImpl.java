package com.idat.ec2.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

import com.idat.ec2.dto.BodegaRequestDTO;
import com.idat.ec2.dto.BodegaResponseDTO;
import com.idat.ec2.model.Bodega;
import com.idat.ec2.repository.BodegaRepository;

public class BodegaServiceImpl implements BodegaService{

	
	@Autowired
	private BodegaRepository repository;
	
	@Override
	public void guardarBodega(BodegaRequestDTO b) {
		// TODO Auto-generated method stub
		Bodega bodegas = new Bodega();
		bodegas.setIdBodega(b.getIdBodegaRequest());
		bodegas.setNombre(b.getNombreBodega());
		bodegas.setDireccion(b.getDireccionBodega());
		repository.save(bodegas);
	}

	@Override
	public void eliminarBodega(Integer id) {
		// TODO Auto-generated method stub
		repository.deleteById(id);
	}

	@Override
	public void editarBodega(BodegaRequestDTO b) {
		// TODO Auto-generated method stub
		Bodega bodegas = new Bodega();
		bodegas.setIdBodega(b.getIdBodegaRequest());
		bodegas.setNombre(b.getNombreBodega());
		bodegas.setDireccion(b.getDireccionBodega());
		repository.saveAndFlush(bodegas);
	}

	@Override
	public List<BodegaResponseDTO> listarBodegas() {
		// TODO Auto-generated method stub
		List<Bodega> bodega = repository.findAll();
		List<BodegaResponseDTO> dto = new ArrayList<BodegaResponseDTO>();
		BodegaResponseDTO bodegaDTO = null;
		
		
		for (Bodega bodegas : bodega) {
			bodegaDTO =  new BodegaResponseDTO();
			bodegaDTO.setIdBodegaResponse(bodegas.getIdBodega());
			bodegaDTO.setNombreBodega(bodegas.getNombre());
			bodegaDTO.setDireccionBodega(bodegas.getDireccion());
		}
		return dto;
	}

	@Override
	public BodegaResponseDTO findById(Integer id) {
		// TODO Auto-generated method stub
		
		Bodega bodegas = repository.findById(id).orElse(null);
		BodegaResponseDTO bodegaDTO = new BodegaResponseDTO();
		
		bodegaDTO.setIdBodegaResponse(bodegas.getIdBodega());
		bodegaDTO.setNombreBodega(bodegas.getNombre());
		bodegaDTO.setDireccionBodega(bodegas.getDireccion());
		
		return bodegaDTO;
	}

}
