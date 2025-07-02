package br.com.techgold.agent;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import br.com.techgold.agent.model.DadosComputador;

public class AgentApplication {
    public static void main(String[] args) {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        
        String token = args[0];
        
        Runnable tarefa = () -> {
            try {
                System.out.println("Coletando dados e enviando...");
                DadosComputador dados = ColetorSistema.coletarDados();
                ApiSender.enviar(dados, token);
            } catch (Exception e) {
                System.err.println("Erro ao executar tarefa: " + e.getMessage());
                e.printStackTrace();
            }
        };

        // Executa a cada 10 minutos, com início imediato
        scheduler.scheduleAtFixedRate(tarefa, 0, 2, TimeUnit.MINUTES);
    }
}