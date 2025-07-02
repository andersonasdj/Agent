package br.com.techgold.agent;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import br.com.techgold.agent.model.DadosComputador;

public class ApiSender {

    //private static final String BEARER_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudC1zeXN0ZW0iLCJpYXQiOjE3NDk4Njk5ODEsImV4cCI6MjA2NTIyOTk4MX0.Exw8CXWs_HUrvcuCCmQ5qnXgaJX5SlBbRdkiLMTTgE4"; 

    public static void enviar(DadosComputador dados, String bearerToken) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.registerModule(new JavaTimeModule());
            mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
            String json = mapper.writeValueAsString(dados);
            
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://app.providerone.com.br/agent/api/v1/computadores"))
//            		.uri(URI.create("http://192.168.0.136:8089/agent/api/v1/computadores"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + bearerToken)
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("Enviado. Status: " + response.statusCode());
            System.out.println("Resposta: " + response.body());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
