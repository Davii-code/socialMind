package com.socialMind.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;
    
    @Value("${app.frontend.url}")
    private String frontendUrl;
    
    @Autowired
    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }
    
    public void sendPasswordResetEmail(String to, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Recuperação de Senha - SocialMind");
        message.setText("Para redefinir sua senha, clique no link abaixo:\n\n" +
                frontendUrl + "/reset-password?token=" + token + "\n\n" +
                "Este link expira em 24 horas.\n\n" +
                "Se você não solicitou a redefinição de senha, ignore este e-mail.");
        
        mailSender.send(message);
    }
}
