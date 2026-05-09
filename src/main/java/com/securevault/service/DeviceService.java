package com.securevault.service;

import com.securevault.dto.DeviceRequest;
import com.securevault.dto.DeviceResponse;
import com.securevault.dto.DevicesResponse;
import com.securevault.entity.Device;
import com.securevault.repository.DeviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class DeviceService {

    private final DeviceRepository deviceRepository;

    @Transactional
    public DeviceResponse registerDevice(UUID userId, DeviceRequest request) {
        if (deviceRepository.existsByDeviceId(request.getDeviceId())) {
            Device existingDevice = deviceRepository.findByDeviceId(request.getDeviceId())
                    .orElseThrow(() -> new IllegalArgumentException("Device already registered"));

            if (!existingDevice.getUserId().equals(userId)) {
                throw new IllegalArgumentException("Device ID already in use");
            }

            existingDevice.setDeviceName(request.getDeviceName());
            existingDevice.setPublicKey(request.getPublicKey());
            existingDevice.updateLastAccessed();
            existingDevice = deviceRepository.save(existingDevice);

            return toResponse(existingDevice);
        }

        Device device = new Device();
        device.setUserId(userId);
        device.setDeviceName(request.getDeviceName());
        device.setDeviceId(request.getDeviceId());
        device.setPublicKey(request.getPublicKey());

        device = deviceRepository.save(device);

        return toResponse(device);
    }

    @Transactional(readOnly = true)
    public DevicesResponse getAllDevices(UUID userId) {
        List<Device> devices = deviceRepository.findByUserId(userId);
        List<DeviceResponse> responses = devices.stream()
                .map(this::toResponse)
                .collect(Collectors.toList());

        return new DevicesResponse(responses, responses.size());
    }

    @Transactional
    public void deleteDevice(UUID userId, String deviceId) {
        Device device = deviceRepository.findByDeviceId(deviceId)
                .orElseThrow(() -> new IllegalArgumentException("Device not found"));

        if (!device.getUserId().equals(userId)) {
            throw new IllegalArgumentException("Access denied");
        }

        deviceRepository.delete(device);
    }

    @Transactional
    public void updateLastAccessed(String deviceId) {
        deviceRepository.findByDeviceId(deviceId).ifPresent(device -> {
            device.updateLastAccessed();
            deviceRepository.save(device);
        });
    }

    private DeviceResponse toResponse(Device device) {
        return new DeviceResponse(
                device.getId().toString(),
                device.getDeviceName(),
                device.getDeviceId(),
                device.getLastAccessedAt(),
                device.getCreatedAt()
        );
    }
}