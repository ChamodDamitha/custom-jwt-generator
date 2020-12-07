package org.custom;

import feign.Feign;
import feign.auth.BasicAuthRequestInterceptor;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.slf4j.Slf4jLogger;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.gateway.dto.JWTInfoDto;
import org.wso2.carbon.apimgt.gateway.handlers.security.jwt.generator.APIMgtGatewayJWTGeneratorImpl;
import org.wso2.carbon.apimgt.gateway.handlers.security.jwt.generator.AbstractAPIMgtGatewayJWTGenerator;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.impl.APIManagerConfigurationService;
import org.wso2.carbon.apimgt.impl.dto.JWTConfigurationDto;
import org.wso2.carbon.apimgt.impl.dto.UserInfoDTO;
import org.wso2.carbon.apimgt.impl.kmclient.ApacheFeignHttpClient;
import org.wso2.carbon.apimgt.impl.kmclient.KMClientErrorDecoder;
import org.wso2.carbon.apimgt.impl.kmclient.KeyManagerClientException;
import org.wso2.carbon.apimgt.impl.kmclient.model.Claim;
import org.wso2.carbon.apimgt.impl.kmclient.model.ClaimsList;
import org.wso2.carbon.apimgt.impl.kmclient.model.TenantHeaderInterceptor;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Map;

@Component(
        enabled = true,
        service = AbstractAPIMgtGatewayJWTGenerator.class,
        name = "customGatewayJWTGenerator"
)
public class CustomJwtGenerator extends APIMgtGatewayJWTGeneratorImpl {

    private static final Log log = LogFactory.getLog(CustomJwtGenerator.class);

    private final String ADMIN_USERNAME = "admin";
    private final String ADMIN_PASSWORD = "admin";
    private final String KEY_MANAGER_IP = "localhost";
    private final String KEY_MANAGER_PORT = "9443";
    private APIManagerConfigurationService apiManagerConfigurationService;

    @Override
    public Map<String, Object> populateCustomClaims(JWTInfoDto jwtInfoDto) {

        Map<String, Object> claims = super.populateCustomClaims(jwtInfoDto);

        // Add user claims
        String username = jwtInfoDto.getEnduser();
        int tenantId = APIUtil.getTenantId(username);
        String tenantDomain = APIUtil.getTenantDomainFromTenantId(tenantId);

        String userInfoEndpoint = "https://" + KEY_MANAGER_IP + ":" + KEY_MANAGER_PORT +
                getTenantAwareContext(tenantDomain).trim() + "/keymanager-operations/user-info";

        try {
            UserClient userClient = Feign.builder()
                    .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(userInfoEndpoint)))
                    .encoder(new GsonEncoder())
                    .decoder(new GsonDecoder())
                    .logger(new Slf4jLogger())
                    .requestInterceptor(new BasicAuthRequestInterceptor(ADMIN_USERNAME, ADMIN_PASSWORD))
                    .requestInterceptor(new TenantHeaderInterceptor(tenantDomain))
                    .errorDecoder(new KMClientErrorDecoder())
                    .target(UserClient.class, userInfoEndpoint);

            String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(username);
            UserInfoDTO userinfo = new UserInfoDTO();
            userinfo.setUsername(tenantAwareUserName);
            if (tenantAwareUserName.contains(CarbonConstants.DOMAIN_SEPARATOR)) {
                userinfo.setDomain(tenantAwareUserName.split(CarbonConstants.DOMAIN_SEPARATOR)[0]);
            }

            APIManagerConfiguration apiManagerConfiguration =
                    this.apiManagerConfigurationService.getAPIManagerConfiguration();
            JWTConfigurationDto jwtConfigurationDto = apiManagerConfiguration.getJwtConfigurationDto();
            String dialectURI = jwtConfigurationDto.getConsumerDialectUri();
            if (!StringUtils.isEmpty(dialectURI)) {
                userinfo.setDialectURI(dialectURI);
            }

            ClaimsList claimsList = userClient.generateClaims(userinfo);
            if (claimsList != null && claimsList.getList() != null) {
                for (Claim claim : claimsList.getList()) {
                    claims.put(claim.getUri(), claim.getValue());
                }
            }
        } catch (APIManagementException | KeyManagerClientException e) {
            log.error("Error in retrieving user claims", e);
        }

        return claims;
    }

    @Reference(
            name = "api.manager.config.service",
            service = org.wso2.carbon.apimgt.impl.APIManagerConfigurationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAPIManagerConfigurationService")
    protected void setAPIManagerConfigurationService(APIManagerConfigurationService amcService) {
        setAPIManagerConfiguration(amcService);
    }

    protected void unsetAPIManagerConfigurationService(APIManagerConfigurationService amcService) {
        setAPIManagerConfiguration(null);
    }

    private void setAPIManagerConfiguration(APIManagerConfigurationService amConfigService) {
        this.apiManagerConfigurationService = amConfigService;
    }

    private String getTenantAwareContext(String tenantDomain) {
        if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            return "/t/".concat(tenantDomain);
        }
        return "";
    }
}
