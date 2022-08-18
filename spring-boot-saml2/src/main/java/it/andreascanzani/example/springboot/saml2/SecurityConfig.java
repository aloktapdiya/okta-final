package it.andreascanzani.example.springboot.saml2;

import java.io.File;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.security.x509.X509Support;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.*;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;




@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Value("${sp.entityBaseURL}")
	private String spEntityBaseURL;

	private static final String LOGIN = "/login";
	@Autowired
	private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
		http
				.authorizeRequests(authorize ->
						authorize.antMatchers("/").permitAll().anyRequest().authenticated()
				).saml2Login();

		http
				.csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());


		http
				.logout()
				.logoutRequestMatcher(new AntPathRequestMatcher("/saml/logout"))
				.deleteCookies("JSESSIONID")
				.logoutSuccessUrl(spEntityBaseURL + LOGIN);
		http
				.headers()
				.frameOptions()
				.disable();
		http
				.sessionManagement()
				.sessionAuthenticationErrorUrl(spEntityBaseURL + LOGIN)
				.invalidSessionUrl(spEntityBaseURL + LOGIN);
		http
				.sessionManagement()
				.maximumSessions(1)
				.expiredUrl(spEntityBaseURL + LOGIN);
		http
				.sessionManagement()
				.sessionFixation()
				.newSession();
		http
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.NEVER);


		// add auto-generation of ServiceProvider Metadata
		Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
		Saml2MetadataFilter filter = new Saml2MetadataFilter(relyingPartyRegistrationResolver, new OpenSamlMetadataResolver());
		http.addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class);
	}


	@Bean
	protected RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {
		ClassLoader classLoader = getClass().getClassLoader();
		File verificationKey = new File(classLoader.getResource("saml-certificate/okta.crt").getFile());
		X509Certificate certificate = X509Support.decodeCertificate(verificationKey);
		Saml2X509Credential credential = Saml2X509Credential.verification(certificate);
		RelyingPartyRegistration registration = RelyingPartyRegistration
				.withRegistrationId("okta-test")
				.assertingPartyDetails(party -> party
						.entityId("http://www.okta.com/exk622k6kcLxjr1oO5d7")
						.singleSignOnServiceLocation("https://dev-45933899.okta.com/app/dev-45933899_oktatest_1/exk622k6kcLxjr1oO5d7/sso/saml")
						.wantAuthnRequestsSigned(false)
						.verificationX509Credentials(c -> c.add(credential))
				).build();
		return new InMemoryRelyingPartyRegistrationRepository(registration);
	}

}
