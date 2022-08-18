package it.andreascanzani.example.springboot.saml2;

import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.w3c.dom.*;
import org.xml.sax.SAXException;

import javax.xml.parsers.*;
import java.io.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
@Controller
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@RequestMapping("/")
	public String index() {
		return "home";
	}

	@RequestMapping("/saml/login")
	public ResponseEntity<String> hello(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) throws ParserConfigurationException, IOException, SAXException, JSONException {
		model.addAttribute("name", principal.getAttributes().toString());
		List<Object> list = new ArrayList<>();
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		String xmlData = auth.getCredentials().toString();
		List<String> resultData = getXMLAttributes(xmlData);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("ID", resultData.get(0));
		jsonObject.put("issueInstance", resultData.get(1));
		return new ResponseEntity<>(jsonObject.toString(), HttpStatus.OK);
	}

	public List<String> getXMLAttributes(String xmlData) throws ParserConfigurationException, IOException, SAXException {
		List<String> resultData = new ArrayList<>();
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		ByteArrayInputStream input = new ByteArrayInputStream(
				xmlData.getBytes("UTF-8"));
		Document doc = builder.parse(input);
		doc.getDocumentElement().normalize();
		Element root = doc.getDocumentElement();
		System.out.println(root.getAttribute("saml2:Assertion"));
		NodeList nList = doc.getElementsByTagName("saml2:Assertion");
		Element eElement = (Element) nList.item(0);
		resultData.add(eElement.getAttribute("ID"));
		resultData.add(eElement.getAttribute("IssueInstant"));
		return resultData;
	}

}
