package com.idat.ec2.service;

import java.util.List;

import com.idat.ec2.dto.ClienteRequestDTO;
import com.idat.ec2.dto.ClienteResponseDTO;

public interface ClienteService {

	public void guardarCliente(ClienteRequestDTO c);
	public void eliminar(Integer id);
	public void editarCliente(ClienteRequestDTO c);
	public List<ClienteResponseDTO> listarCliente();
	public ClienteResponseDTO clienteById(Integer id);
}
