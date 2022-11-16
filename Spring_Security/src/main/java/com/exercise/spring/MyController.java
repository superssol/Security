package com.exercise.spring;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;


@Controller
public class MyController {
	
	@RequestMapping("/")
	public @ResponseBody String root() throws Exception {
		return "Security-loginForm";
	}
	
	@RequestMapping("/guest/welcome")
	public String welcome2() {
		
		return "guest/welcome2";
	}
	
	@RequestMapping("/member/welcome")
	public String welcome3() {
		
		return "member/welcome3";
	}
	
	@RequestMapping("/admin/welcome")
	public String welcome1() {
		
		return "admin/welcome1";
	}
	
	@RequestMapping("/loginForm")
	public String loginForm() {
		
		return "security/loginForm";
	}
	
	@RequestMapping("/loginError")
	public String loginError() {
		
		return "security/loginError";
	}
}
