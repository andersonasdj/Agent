package br.com.techgold.agent;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import br.com.techgold.agent.model.DadosComputador;
import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.ComputerSystem;
import oshi.hardware.Firmware;
import oshi.hardware.GlobalMemory;
import oshi.hardware.GraphicsCard;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.hardware.NetworkIF;
import oshi.hardware.PhysicalMemory;
import oshi.software.os.NetworkParams;
import oshi.software.os.OSFileStore;
import oshi.software.os.OperatingSystem;

public class ColetorSistema {
	private static String getDomainName() {
	    String os = System.getProperty("os.name").toLowerCase();

	    try {
	        if (os.contains("win")) {
	            // PowerShell para obter o domínio (ou grupo de trabalho)
	            Process process = Runtime.getRuntime().exec("powershell -Command \"(Get-WmiObject Win32_ComputerSystem).Domain\"");
	            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
	            String domain = reader.readLine();
	            process.waitFor();
	            return (domain != null && !domain.trim().isEmpty()) ? domain.trim() : "Desconhecido";
	        } else {
	            // Linux: tenta hostname -d (domínio DNS)
	            Process process = Runtime.getRuntime().exec("hostname -d");
	            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
	            String domain = reader.readLine();
	            process.waitFor();
	            return (domain != null && !domain.trim().isEmpty()) ? domain.trim() : "Desconhecido";
	        }
	    } catch (Exception e) {
	        return "Erro ao obter domínio";
	    }
	}
	
	private static String detectarTipoEquipamento() {
	    String os = System.getProperty("os.name").toLowerCase();

	    try {
	        if (os.contains("win")) {
	            Process process = Runtime.getRuntime().exec(
	                "powershell -Command \"(Get-WmiObject Win32_SystemEnclosure).ChassisTypes\"");
	            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
	            String line = reader.readLine();
	            process.waitFor();

	            if (line != null && !line.trim().isEmpty()) {
	                int tipo = Integer.parseInt(line.trim());

	                switch (tipo) {
	                    case 8: case 9: case 10: case 14:
	                        return "Notebook";
	                    case 30:
	                        return "All-in-One";
	                    case 13:
	                        return "All-in-One";
	                    case 3:
	                        return "Desktop";
	                    case 23:
	                        return "Servidor";
	                    case 7:
	                        return "Servidor";
	                    default:
	                        return "Outro (" + tipo + ")";
	                }
	            }
	        }
	    } catch (Exception e) {
	        return "Desconhecido";
	    }

	    return "Desconhecido";
	}
	
	public static DadosComputador coletarDados() {

	    SystemInfo si = new SystemInfo();
	    HardwareAbstractionLayer hal = si.getHardware();
	    OperatingSystem os = si.getOperatingSystem();

	    GlobalMemory memory = hal.getMemory();
	    CentralProcessor cpu = hal.getProcessor();
	    List<NetworkIF> redes = hal.getNetworkIFs();
	    ComputerSystem system = hal.getComputerSystem();
	    DadosComputador dados = new DadosComputador();

	    // OS
	    dados.os = os.toString();
	    dados.platform = os.getFamily();

	    // Versão e build do OS
	    var versionInfo = os.getVersionInfo();
	    if (versionInfo != null) {
	        dados.osVersion = versionInfo.getVersion();
	        dados.osBuildNumber = versionInfo.getBuildNumber();
	    } else {
	        dados.osVersion = "N/A";
	        dados.osBuildNumber = "N/A";
	    }

	    // Arquitetura
	    String arch = System.getProperty("os.arch");
	    if (arch == null || arch.isEmpty()) {
	        arch = System.getenv("PROCESSOR_ARCHITECTURE");
	    }
	    dados.osArchitecture = arch != null ? arch : "Desconhecido";

	    // Timezone
	    dados.timeZone = java.time.ZoneId.systemDefault().toString();

	    // Uptime do sistema
	    dados.systemUptimeSeconds = os.getSystemUptime();

	    // Hostname
	    dados.name = os.getNetworkParams().getHostName();

	    // Domínio
	    dados.domain = getDomainName();

	    dados.deviceType = detectarTipoEquipamento();

	    // IPs
	    List<String> ips = new ArrayList<>();
	    if (!redes.isEmpty()) {
	        for (NetworkIF rede : redes) {
	            rede.updateAttributes();
	            String[] ipv4s = rede.getIPv4addr();
	            for (String ip : ipv4s) {
	                if (!ip.startsWith("127.")) {
	                    ips.add(ip);
	                }
	            }
	        }
	    }
	    dados.ipAddresses = ips;

	    // CPU
	    dados.cpu = cpu.getProcessorIdentifier().getName() + " (" + cpu.getPhysicalProcessorCount() + " cores, "
	            + cpu.getLogicalProcessorCount() + " threads)";

	    long[] freqs = cpu.getCurrentFreq();
	    if (freqs.length > 0 && freqs[0] > 0) {
	        dados.cpuFrequencyGHz = freqs[0] / 1e9;
	    } else if (cpu.getMaxFreq() > 0) {
	        dados.cpuFrequencyGHz = cpu.getMaxFreq() / 1e9;
	    } else {
	        dados.cpuFrequencyGHz = 0.0;
	    }

	    // RAM
	    dados.ram = String.format("%.2f GB", memory.getTotal() / 1073741824.0);
	    dados.ramAvailable = String.format("%.2f GB", memory.getAvailable() / 1073741824.0);

	    // Memória física por slot
	    List<String> memSlots = new ArrayList<>();
	    for (PhysicalMemory mem : memory.getPhysicalMemory()) {
	        memSlots.add(mem.getBankLabel() + ": " + String.format("%.2f GB", mem.getCapacity() / 1073741824.0));
	    }
	    dados.memorySlots = memSlots;

	    // Espaço em disco + BitLocker
	    List<OSFileStore> fileStores = os.getFileSystem().getFileStores();
	    List<String> discos = new ArrayList<>();
	    List<String> discosDisponiveis = new ArrayList<>();
	    List<String> recoveryKeys = new ArrayList<>();

	    for (OSFileStore fs : fileStores) {
	        fs.updateAttributes();
	        String mount = fs.getMount();
	        String letraUnidade = mount.length() >= 1 ? mount.substring(0, 1) : "";
	        String total = String.format("%.2f GB", fs.getTotalSpace() / 1e9);
	        String disponivel = String.format("%.2f GB", fs.getUsableSpace() / 1e9);

	        discos.add(mount + ": " + total);
	        discosDisponiveis.add(mount + ": " + disponivel);

	        try {
	            String psScript = String.format(
	                    "$result = New-Object System.Collections.ArrayList; " +
	                    "$currentOutput = '' | Select-Object 'Mount Point', 'Volume Type', 'Recovery Key', 'Protection Status', A1_Key; " +
	                    "if (Get-Command 'Get-BitLockerVolume' -ErrorAction SilentlyContinue) { " +
	                    "$bitlocker = Get-BitLockerVolume -MountPoint '%s'; } " +
	                    "$currentOutput.'Volume Type' = if ($bitlocker) { $bitlocker.VolumeType } else { 'System' }; " +
	                    "$currentOutput.'Mount Point' = if ($bitlocker) { $bitlocker.MountPoint } else { 'System' }; " +
	                    "$currentOutput.'Protection Status' = if ($bitlocker) { $bitlocker.Protectionstatus } else { 'BitLocker module is unavailable' }; " +
	                    "$currentOutput.'Recovery Key' = if ($bitlocker) { [string]$bitlocker.KeyProtector.Recoverypassword } else { 'Unavailable' }; " +
	                    "$currentOutput.A1_Key = 'none'; " +
	                    "$result.Add($currentOutput) | Out-Null; " +
	                    "$result | Format-List",
	                    letraUnidade
	            );

	            String[] comando = {"powershell.exe", "-Command", psScript};
	            Process process = new ProcessBuilder(comando).redirectErrorStream(true).start();
	            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
	            String linha;
	            String recovery = null;

	            while ((linha = reader.readLine()) != null) {
	                if (linha.trim().startsWith("Recovery Key")) {
	                    recovery = linha.split(":", 2)[1].trim();
	                    if (!recovery.equalsIgnoreCase("Unavailable")) {
	                        recoveryKeys.add(letraUnidade + ": " + recovery);
	                    }
	                    break;
	                }
	            }

	            process.waitFor();
	        } catch (Exception e) {
	            recoveryKeys.add(letraUnidade + ": Erro ao coletar chave");
	        }
	    }

	    dados.disk = discos;
	    dados.diskAvailable = discosDisponiveis;
	    dados.bitlockerRecoveryKeys = recoveryKeys.isEmpty()
	            ? List.of("Nenhuma chave encontrada")
	            : recoveryKeys;

	    // Rede
	    if (!redes.isEmpty()) {
	        NetworkIF principal = redes.get(0);
	        principal.updateAttributes();
	        dados.mac = principal.getMacaddr();
	        long speedBps = principal.getSpeed();
	        dados.networkSpeedMbps = speedBps > 0 ? speedBps / 1_000_000 : 0;
	    }

	    // DNS e Gateway
	    NetworkParams params = os.getNetworkParams();
	    dados.gateway = params.getIpv4DefaultGateway();
	    dados.dnsServers = Arrays.asList(params.getDnsServers());

	    // GPU
	    List<String> gpus = new ArrayList<>();
	    for (GraphicsCard gpu : hal.getGraphicsCards()) {
	        gpus.add(gpu.getName() + " - VRAM: " + String.format("%.2f GB", gpu.getVRam() / 1e9));
	    }
	    dados.gpus = gpus;

	    // BIOS
	    Firmware fw = system.getFirmware();
	    dados.biosVersion = fw.getVersion() != null ? fw.getVersion() : "Indisponível";
	    dados.biosVendor = fw.getManufacturer() != null ? fw.getManufacturer() : "Indisponível";
	    dados.biosReleaseDate = fw.getReleaseDate() != null ? fw.getReleaseDate() : "Indisponível";

	    // Monitores
	    dados.monitores = hal.getDisplays().size();

	    // UUID
	    dados.uuid = system.getHardwareUUID() != null ? system.getHardwareUUID() : "Indisponivel";

	    // Detecta VM
	    dados.isVirtualMachine = system.getModel().toLowerCase().contains("virtual") ||
	            system.getManufacturer().toLowerCase().contains("vmware");

	    // Fabricante / Serial / Modelo
	    dados.manufacturer = system.getManufacturer();
	    dados.serial = system.getSerialNumber();
	    dados.device_name = system.getModel();

	    // Tempo de Boot
	    long bootTime = os.getSystemBootTime();
	    dados.lastBootTime = LocalDateTime.ofEpochSecond(bootTime, 0,
	            ZoneOffset.systemDefault().getRules().getOffset(Instant.now()));

	    // **Usuário logado**
	    dados.username = getLoggedOnUser();

	    // Datas do agente
	    dados.agentInstallDate = LocalDateTime.now().withNano(0);
	    dados.lastSeen = LocalDateTime.now();
	    dados.status = "ONLINE";
	    dados.type = "AGENT";

	    // Antivírus
	    try {
	        Process process = Runtime.getRuntime().exec(
	            "powershell -Command \"Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntivirusProduct | Select-Object displayName\""
	        );
	        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
	        StringBuilder avNames = new StringBuilder();
	        String line;
	        while ((line = reader.readLine()) != null) {
	            line = line.trim();
	            if (!line.isEmpty() && !line.equals("displayName")) {
	                avNames.append(line).append(", ");
	            }
	        }
	        process.waitFor();
	        dados.antivirus = avNames.toString().replaceAll(", $", "");
	    } catch (Exception e) {
	        dados.antivirus = "Erro ao coletar antivírus";
	    }

	    return dados;
	}

    
    private static String getLoggedOnUser() {
        // 1. Primeiro tenta via WMI
        try {
            Process process = Runtime.getRuntime().exec(
                "powershell -Command \"(Get-WmiObject -Class Win32_ComputerSystem).UserName\""
            );
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String user = reader.readLine();
            process.waitFor();
            if (user != null && !user.trim().isEmpty()) {
                return user.trim();
            }
        } catch (Exception ignored) {}

        // 2. Fallback usando "query user"
        try {
            Process process = Runtime.getRuntime().exec("query user");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.trim().startsWith("USERNAME") && !line.trim().isEmpty()) {
                    String[] tokens = line.trim().split("\\s+");
                    if (tokens.length > 0) {
                        return tokens[0];
                    }
                }
            }
        } catch (Exception e) {
            return "Desconhecido";
        }

        return "Desconhecido";
    }

    
}