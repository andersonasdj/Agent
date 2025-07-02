package br.com.techgold.agent.model;

import java.time.LocalDateTime;
import java.util.List;

public class DadosComputador {
    public String name;
    public String mac;
    public String os;
    public String osVersion;
    public String osBuildNumber;
    public String osArchitecture;
    public String timeZone;
    public String cpu;
    public double cpuFrequencyGHz;
    public String ram;
    public String ramAvailable;
    public List<String> disk;
    public List<String> diskAvailable;
    public String platform;
    public String status;
    public String address;
    public List<String> ipAddresses;
    public long networkSpeedMbps;
    public String type;
    public String comment;
    public String serial;
    public String device_name;
    public String manufacturer;
    public LocalDateTime lastSeen;
    public LocalDateTime agentInstallDate;
    public LocalDateTime lastBootTime;
    public Long clienteId;
    public Long funcionarioId;
    public String username;
    public long systemUptimeSeconds;
    public List<String> memorySlots;
    public String gateway;
    public List<String> dnsServers;
    public List<String> gpus;
    public String biosVersion;
    public String biosVendor;
    public String biosReleaseDate;
    public int monitores;
    public String uuid;
    public boolean isVirtualMachine;
    public String domain;
    public String deviceType;
    public String antivirus;
    public List<String> bitlockerRecoveryKeys;
    public boolean storageMonitor;
    public boolean statusMonitor;

    
}