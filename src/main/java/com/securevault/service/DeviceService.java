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

/**
 * Service for managing user devices in the password manager.
 *
 * This service allows users to:
 * - Register new devices (e.g., phone, tablet, computer) for vault access
 * - Track which devices have been used to access the vault
 * - Revoke device access by removing registered devices
 *
 * DEVICE MANAGEMENT:
 * - Each device is identified by a unique device ID
 * - Devices can have a public key for end-to-end encryption scenarios
 * - Device names help users identify their registered devices
 * - Last accessed timestamp tracks recent device activity
 *
 * SECURITY CONSIDERATIONS:
 * - Users can only manage their own devices
 * - Device registration requires valid authentication
 * - Device removal is immediate and permanent
 * - Public keys enable future end-to-end encryption features
 *
 * USE CASES:
 * - View all devices logged into the account
 * - Remove old/unused devices
 * - Track device activity for security auditing
 * - Support for multiple devices (mobile + desktop apps)
 */
@Service
@RequiredArgsConstructor
public class DeviceService {

    private final DeviceRepository deviceRepository;

    /**
     * Registers a new device or updates an existing one.
     *
     * If the device ID already exists for this user, it updates the device info.
     * If the device ID exists for another user, registration is denied.
     * If the device ID is new, it creates a new device registration.
     *
     * @param userId UUID of the user registering the device
     * @param request Contains deviceId, deviceName, and optionally publicKey
     * @return DeviceResponse with the registered device details
     * @throws IllegalArgumentException if device ID is already in use by another user
     */
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

    /**
     * Retrieves all devices registered for a user.
     *
     * Returns a list of all devices the user has used to access their vault,
     * including device names, IDs, and last access times.
     *
     * @param userId UUID of the user
     * @return DevicesResponse containing list of devices and total count
     */
    @Transactional(readOnly = true)
    public DevicesResponse getAllDevices(UUID userId) {
        List<Device> devices = deviceRepository.findByUserId(userId);
        List<DeviceResponse> responses = devices.stream()
                .map(this::toResponse)
                .collect(Collectors.toList());

        return new DevicesResponse(responses, responses.size());
    }

    /**
     * Removes a device from the user's registered devices.
     *
     * Permanently deletes the device registration. The device will no longer
     * appear in the user's device list and cannot be used to access the vault
     * (unless re-registered).
     *
     * @param userId UUID of the user
     * @param deviceId String ID of the device to remove
     * @throws IllegalArgumentException if device not found or access denied
     */
    @Transactional
    public void deleteDevice(UUID userId, String deviceId) {
        Device device = deviceRepository.findByDeviceId(deviceId)
                .orElseThrow(() -> new IllegalArgumentException("Device not found"));

        if (!device.getUserId().equals(userId)) {
            throw new IllegalArgumentException("Access denied");
        }

        deviceRepository.delete(device);
    }

    /**
     * Updates the last accessed timestamp for a device.
     *
     * Called when a device successfully authenticates to track usage.
     * This helps users see which devices are actively being used.
     *
     * @param deviceId String ID of the device
     */
    @Transactional
    public void updateLastAccessed(String deviceId) {
        deviceRepository.findByDeviceId(deviceId).ifPresent(device -> {
            device.updateLastAccessed();
            deviceRepository.save(device);
        });
    }

    /**
     * Converts a Device entity to a DeviceResponse DTO.
     *
     * @param device Database entity
     * @return Response DTO with device details
     */
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