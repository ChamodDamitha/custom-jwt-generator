package org.custom;

import feign.Headers;
import feign.Param;
import feign.RequestLine;
import org.wso2.carbon.apimgt.impl.dto.UserInfoDTO;
import org.wso2.carbon.apimgt.impl.kmclient.KeyManagerClientException;
import org.wso2.carbon.apimgt.impl.kmclient.model.ClaimsList;

public interface UserClient {
    @Headers("Content-Type: application/json")
    @RequestLine("POST /claims/generate")
    ClaimsList generateClaims(UserInfoDTO userinfo) throws KeyManagerClientException;

    @RequestLine("GET /claims?username={username}&domain={domain}&dialect={dialect}")
    ClaimsList getClaims(@Param("username") String username, @Param("domain") String domain,
                         @Param("dialect") String dialect) throws KeyManagerClientException;

}
