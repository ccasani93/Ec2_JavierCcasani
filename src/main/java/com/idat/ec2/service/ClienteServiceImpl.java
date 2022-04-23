package com.idat.ec2.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.idat.ec2.dto.ClienteRequestDTO;
import com.idat.ec2.dto.ClienteResponseDTO;
import com.idat.ec2.model.Cliente;
import com.idat.ec2.repository.ClienteRepository;

@Service
public class ClienteServiceImpl implements ClienteService {

	@Autowired
	private ClienteRepository repository;
	
	@Override
	public void guardarCliente(ClienteRequestDTO c) {
		// TODO Auto-generated method stub

		Cliente clientes = new Cliente();
		clientes.setNombre(c.getNombreCliente());
		clientes.setDireccion(c.getDireccionCliente());
		clientes.setDni(c.getDniCliente());
		clientes.setIdCliente(c.getIdClienteRequest());
		repository.save(clientes);
	}

	@Override
	public void eliminar(Integer id) {
		// TODO Auto-generated method stub

		repository.deleteById(id);
	}

	@Override
	public void editarCliente(ClienteRequestDTO c) {
		// TODO Auto-generated method stub

		Cliente clientes = new Cliente();
		clientes.setIdCliente(c.getIdClienteRequest());
		clientes.setNombre(c.getNombreCliente());
		clientes.setDireccion(c.getDireccionCliente());
		clientes.setDni(c.getDniCliente());
		repository.saveAndFlush(clientes);
		
	}

	@Override
	public List<ClienteResponseDTO> listarCliente() {
		// TODO Auto-generated method stub
		
		List<Cliente> cliente = repository.findAll();
		List<ClienteResponseDTO> dto = new ArrayList<ClienteResponseDTO>();
		ClienteResponseDTO clienteDTO = null;
		
		for (Cliente clientes : cliente) {
			clienteDTO = new ClienteResponseDTO();
			clienteDTO.setIdClienteResponse(clientes.getIdCliente());
			clienteDTO.setNombreCliente(clientes.getNombre());
			clienteDTO.setDireccionCliente(clientes.getDireccion());			
			clienteDTO.setDniCliente(clientes.getDni());
			
		}
		
		return dto;
	}

	@Override
	public ClienteResponseDTO clienteById(Integer id) {
		// TODO Auto-generated method stub
		
		Cliente clientes = repository.findById(id).orElse(null);
		ClienteResponseDTO clienteDTO = new ClienteResponseDTO();
		
		clienteDTO = new ClienteResponseDTO();
		clienteDTO.setIdClienteResponse(clientes.getIdCliente());
		clienteDTO.setNombreCliente(clientes.getNombre());
		clienteDTO.setDireccionCliente(clientes.getDireccion());			
		clienteDTO.setDniCliente(clientes.getDni());
				
					
		return clienteDTO;
	}

}
