/*
 * $Revision: 8843 $
 * $Date: 2014-09-26 12:00:41 +0800 (周五, 26 九月 2014) $
 * $Id: MLoginManagerImpl.java 8843 2014-09-26 04:00:41Z hejianliang $
 * ====================================================================
 * Copyright © 2012 Beijing seeyon software Co..Ltd..All rights reserved.
 *
 * This software is the proprietary information of Beijing seeyon software Co..Ltd.
 * Use is subject to license terms.
 */
package com.seeyon.apps.m1.login.manager.impl;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.CharArrayBuffer;
import org.apache.http.util.EntityUtils;

import com.alibaba.fastjson.JSON;
import com.seeyon.apps.ldap.util.LDAPTool;
import com.seeyon.apps.m1.authorization.mobileAuth.service.MobileAuthService;
import com.seeyon.apps.m1.bind.service.MClientBindService;
import com.seeyon.apps.m1.common.bo.workflow.MSignatureUtils;
import com.seeyon.apps.m1.common.utils.MAppContextUtils;
import com.seeyon.apps.m1.common.utils.MDesUtil;
import com.seeyon.apps.m1.common.utils.MHttpServletRequest;
import com.seeyon.apps.m1.common.vo.MConstant;
import com.seeyon.apps.m1.common.vo.MErrorConstants;
import com.seeyon.apps.m1.common.vo.datatype.MBoolean;
import com.seeyon.apps.m1.common.vo.datatype.MString;
import com.seeyon.apps.m1.login.bo.MLoginUtils;
import com.seeyon.apps.m1.login.manager.MLoginManager;
import com.seeyon.apps.m1.login.parameters.MLoginParameter;
import com.seeyon.apps.m1.login.vo.MLoginResult;
import com.seeyon.apps.m1.message.bo.MMessageUtils;
import com.seeyon.apps.m1.message.cache.MMessageCache;
import com.seeyon.apps.m1.message.listener.MMessageEventListener;
import com.seeyon.apps.m1.message.manager.MMessageManager;
import com.seeyon.apps.m1.message.vo.MPushMessageListItem;
import com.seeyon.apps.m1.message.vo.MPushOperateMessageListItem;
import com.seeyon.apps.m1.message.vo.pushconfig.MMessageConfig;
import com.seeyon.apps.m1.message.vo.pushconfig.MUserMessagePushConfig;
import com.seeyon.apps.m1.organization.bo.MOrganizationUtils;
import com.seeyon.apps.m1.organization.manager.MOrganizationManager;
import com.seeyon.apps.m1.organization.vo.MOrgMember;
import com.seeyon.apps.m1.product.manager.MProductManager;
import com.seeyon.apps.m1.third.manager.MDidicarManager;
import com.seeyon.cmp.authentication.CMPAuthenticationContants;
import com.seeyon.cmp.authentication.ICMPSSOLogout;
import com.seeyon.ctp.common.AppContext;
import com.seeyon.ctp.common.authenticate.domain.User;
import com.seeyon.ctp.common.cache.CacheAccessable;
import com.seeyon.ctp.common.cache.CacheFactory;
import com.seeyon.ctp.common.cache.CacheMap;
import com.seeyon.ctp.common.constants.LoginResult;
import com.seeyon.ctp.common.constants.SystemProperties;
import com.seeyon.ctp.common.exceptions.BusinessException;
import com.seeyon.ctp.common.flag.SysFlag;
import com.seeyon.ctp.common.i18n.LocaleContext;
import com.seeyon.ctp.common.i18n.ResourceUtil;
import com.seeyon.ctp.common.po.usermapper.CtpOrgUserMapper;
import com.seeyon.ctp.common.thirdparty.ThirdpartyTicketManager;
import com.seeyon.ctp.common.usermapper.dao.UserMapperDao;
import com.seeyon.ctp.login.LoginControl;
import com.seeyon.ctp.login.online.OnlineRecorder;
import com.seeyon.ctp.organization.OrgConstants;
import com.seeyon.ctp.organization.bo.V3xOrgAccount;
import com.seeyon.ctp.organization.bo.V3xOrgMember;
import com.seeyon.ctp.organization.manager.OrgManager;
import com.seeyon.ctp.portal.customize.manager.CustomizeManager;
import com.seeyon.ctp.util.Strings;
import com.seeyon.ctp.util.json.JSONUtil;

/**
 * 登录管理器实现
 * 
 * @author wangx
 * @since JDK 1.5
 * @version 1.0
 */
public class MLoginManagerImpl implements MLoginManager {
	// 取得缓存管理工厂实例
   
    private static final Log log = LogFactory.getLog(MLoginManagerImpl.class);
    // 取得缓存管理工厂实例
    private static CacheAccessable mLoginfactory = CacheFactory.getInstance(MLoginManagerImpl.class);
    
    // 创建缓存
    public static CacheMap<Long, String> client = mLoginfactory.createMap("clientCache");
    public static CacheMap<String, String> sessionMapper = mLoginfactory.createMap("mSessionMapper");
    public static CacheMap<Long, String> bindedMap = mLoginfactory.createMap("bindedMapCache");
    private LoginControl loginControl;
    private MOrganizationManager mOrgManager;
    private MProductManager mProductManager;
    private MobileAuthService mobileAuthService;
    private OrgManager orgManager;
    private MMessageManager mMessageManager;
    private MClientBindService mClientBindService;
    private UserMapperDao userMapperDao;
    private CustomizeManager customizeManager;
    private static int m1version = 510;
    private static String unlogininfo = ResourceUtil.getString("m1.login.version.mismatch");// "客户端版本与服务器版本不匹配，不能登录！";
    private ICMPSSOLogout ssoLogout;
    private MDidicarManager mDidicarManager;
    private String eRrorMessage;
    @Override
    public MLoginResult transLogin(MLoginParameter loginParameter) throws BusinessException {
        String cv = loginParameter.getClientVersion();
        if (Strings.isNotBlank(cv)) {
            int s = Integer.parseInt(cv.substring(0, 1));
            if (s >= 5) {
                cv = cv.replace(".", "");
                int vs = Integer.parseInt(cv);
                if (vs < m1version) {
                    throw new BusinessException(unlogininfo);
                }
            }
        } else {
            throw new BusinessException(unlogininfo);
        }
        //从安卓端拿到品高船体过来的ssourl和acccesToken参数
        Map<String, Object> mExtAttrs=loginParameter.getExtAttrs();
        if(null!=mExtAttrs){
        	String acccesToken = (String) mExtAttrs.get("acccesToken");
            String refreshToken = (String) mExtAttrs.get("refreshToken");
            String ssoUrl = (String) mExtAttrs.get("ssoUrl");
            String uamUrl = (String) mExtAttrs.get("uamUrl");
            log.info("品高系统传递过来的参数:(1)acccesToken="+acccesToken+";(2)refreshToken="+refreshToken+";(3)ssoUrl="+ssoUrl+";(4)uamUrl="+uamUrl);
            //向品高系统发送get请求，验证acccesToken的有效性,并返回用户信息（其中没有密码）
            String mResult=null;
            String linkUrl=ssoUrl+"/oauth2/userinfo?access_token="+acccesToken;
            if(Strings.isNotBlank(ssoUrl) && Strings.isNotBlank(acccesToken) && !"null".equals(acccesToken)){
            	mResult=get(linkUrl);
            }
            log.info("品高系统返回的用户信息:mResult="+mResult);
            if(Strings.isNotBlank(mResult)){
            	Map map=JSON.parseObject(mResult, Map.class);
            	String name= (String) map.get("name");
            	String username= (String) map.get("username");
            	String phone_number= (String) map.get("phone_number");
            	String login_name= (String) map.get("login_name");
            	String uid= (String) map.get("uid");
            	log.info("解析品高系统返回的用户信息：(1)name="+name+";(2)username="+username+";(3)phone_number="+phone_number+";(4)login_name="+login_name+";(5)uid="+uid);
            	loginParameter.setUsername(MDesUtil.encode(phone_number));
                loginParameter.setPassword(MDesUtil.encode(""));//因为这里密码为null的时候，不会进入CustomLoginAuthentication拦截器，就不能只通过用户名登录，所以静态设置一个空字符串
            }else{
            	throw MAppContextUtils.getException(MErrorConstants.C_iCommon_Link_AccessException + "",ResourceUtil.getString("m1.bind.login.accesslink")+linkUrl+";"+eRrorMessage);
            }
        }
//        
//        loginParameter.setUsername(MDesUtil.encode("zy2"));
//        loginParameter.setPassword(MDesUtil.encode(""));
        
        HttpServletRequest request = AppContext.getRawRequest();
        HttpServletResponse response = AppContext.getRawResponse();
        HttpSession session = AppContext.getRawSession();
        MHttpServletRequest mRequest = new MHttpServletRequest(request);
        if(loginParameter.getLocal() != null){
        	Locale local = new Locale(loginParameter.getLocal());
            LocaleContext.setLocale(session, local);
        }
        MLoginUtils.fillRequest(mRequest, loginParameter);
        LoginResult loginResult = null;

        /*
         * if(!SeeyonVSMUtils.checkRequest(mRequest)) { throw new
         * BusinessException(ResourceUtil.getString("m1.request.unknowserver"));
         * }
         */
        V3xOrgMember mb = null;

        // 如果是注册授权，需要进行判断
        if (mProductManager.getType() == 2 && Strings.isNotBlank(loginParameter.getUsername())) {
            mb = orgManager.getMemberByLoginName(loginParameter.getUsername().trim());
            if (mb == null) {
                CtpOrgUserMapper ep = userMapperDao.getLoginName(loginParameter.getUsername().trim(), LDAPTool
                        .catchLDAPConfig().getType());
                if (null != ep) {
                    mb = orgManager.getMemberById(ep.getMemberId());
                }
            }
            if (mb != null && mb.getEnabled() && mb.getState() == OrgConstants.MEMBER_STATE.ONBOARD.ordinal()) {
                Long memberID = mb.getId();
                boolean flag = mobileAuthService.userAuthedFlag(memberID);
                if (!flag) {
                    throw MAppContextUtils.getException(MErrorConstants.C_iLogin_Tip_Unauthorized + "",
                            ResourceUtil.getString("m1.login.Unauthorized"));
                }
            } else {
                log.info("*********************没有查到 " + loginParameter.getUsername() + "    这个用户 .");
                throw MAppContextUtils.getException(MErrorConstants.C_iLogin_Tip_Invalid + "",
                        ResourceUtil.getString("m1.login.UserNotexist"));
            }
        }
        if (Strings.isNotBlank(loginParameter.getUsername()) && Strings.isNotBlank(loginParameter.getDeviceCode())) {
            mb = orgManager.getMemberByLoginName(loginParameter.getUsername().trim());
            if (mb == null) {
                CtpOrgUserMapper ep = userMapperDao.getLoginName(loginParameter.getUsername().trim(), LDAPTool
                        .catchLDAPConfig().getType());
                if (null != ep) {
                    mb = orgManager.getMemberById(ep.getMemberId());
                }
            }
            if (mb != null) {
                long memberID = mb.getId();
                int loginType = loginParameter.getLoginType();
                int result = mClientBindService.loginCheckByBind(loginParameter.getDeviceCode(), memberID, loginType,
                        mb.getOrgAccountId());

                if (result == 2) {
                    // forbidden
                    throw MAppContextUtils.getException(MErrorConstants.C_iLogin_Tip_Forbidden + "",
                            ResourceUtil.getString("m1.bind.login.forbidden"));
                } else if (result == 1) {
                    // 没绑定 但是安全级别是高，需要绑定申请
                    throw MAppContextUtils.getException(MErrorConstants.C_iLogin_Tip_NeedBind + "",
                            ResourceUtil.getString("m1.bind.login.highsafelevel.apply"));

                } else if (result == 3) {
                    // 设备被其他用户绑定
                    throw MAppContextUtils.getException(MErrorConstants.C_iLogin_Tip_BindByOthers + "",
                            ResourceUtil.getString("m1.bind.login.apply.binded"));
                }
                String clientType = loginType == MLoginParameter.C_iLoginType_iPad ? "iPad"
                        : loginType == MLoginParameter.C_iLoginType_iPhone ? "iPhone" : "android";
                if ("android".equals(clientType)) {
                    bindedMap.put(memberID, loginParameter.getDeviceCode());
                } else {
                    String[] info = loginParameter.getDeviceCode().split("\\|");
                    if (info.length == 2) {
                        bindedMap.put(memberID, info[1]);
                    }
                }
            }
        }
        try {
        	if (mb != null && "secret-admin".equals(mb.getLoginName())) {
        		throw new BusinessException("管理员不能登录");
        	}
            loginResult = loginControl.transDoLogin(mRequest, session, response);
        } catch (Throwable e) {
            getBusinessException(e);
        }
        User user = AppContext.getCurrentUser();
        if (user != null) {
            Locale locale = MLoginUtils.setLocale(loginParameter, mRequest);
            user.setLocale(locale);
        }
        MLoginResult result = new MLoginResult();
        Map<String, Object> extAttrs = new HashMap<String,Object>();
        result.setLoginResult((loginResult != null) ? loginResult.getStatus() : -1);
        MOrgMember member = mOrgManager.getMemberNotNeedCount(AppContext.currentUserLoginName());
        result.setCurrentUser(member);
        result.setToken(session.getId());
        sessionMapper.put(user.getLoginName(), result.getToken());//将session放置到缓存中，用于后续处理表单时使用
        result.setResourceList(null); // TODO 由于资源这块服务器端还未最终确定所以暂不设置
        result.setHasSignetures(true);//MSignatureUtils.checkHasSignetureManager());
        result.setGroupVer((Boolean) (SysFlag.sys_isGroupVer.getFlag()));
        result.setGovVer((Boolean) (SysFlag.sys_isGovVer.getFlag()));
        if (AppContext.hasPlugin("moffice")) {
            result.setHasOfficePlugin(true);
        } 
        String ssoTicket = (String) request.getAttribute(CMPAuthenticationContants.TICKET);
        if(ssoTicket == null) {
        	ssoTicket = ThirdpartyTicketManager.getInstance().newTicketInfo("xc", user.getLoginName());
        }
        extAttrs.put(CMPAuthenticationContants.TICKET, ssoTicket);
        extAttrs.put("track_send", customizeManager.getCustomizeValue(member.getOrgID(), "track_send"));
        extAttrs.put("track_process", customizeManager.getCustomizeValue(member.getOrgID(), "track_process"));
        String didicarConfig = this.getDidicarConfig(member.getOrgID());
        if(Strings.isNotBlank(didicarConfig)){
        	extAttrs.put("didicarConfig", didicarConfig);
        }
        extAttrs.put("didicar.cloud.url",AppContext.getSystemProperty("didicar.cloud.url"));

        result.setExtAttrs(extAttrs);
        
        return result;
    }
    private String getDidicarConfig(Long memberID) {
    	MString config;
		try {
			if(mDidicarManager != null) {
				config = this.mDidicarManager.getdidiCarConfig(memberID);
				if(config != null){
		    		return config.getValue();
		    	}
			}
		} catch (Exception e) {
			log.warn(" load  didicar config failed !! because  " + e);
		}
    	
    	return null;
    }
    private MLoginResult initMPlugin(MLoginResult result) throws BusinessException{
    	result.setHasSignetures(MSignatureUtils.checkHasSignetureManager());
        result.setGroupVer((Boolean) (SysFlag.sys_isGroupVer.getFlag()));
        result.setGovVer((Boolean) (SysFlag.sys_isGovVer.getFlag()));
        if (AppContext.hasPlugin("moffice")) {
            result.setHasOfficePlugin(true);
        }

    	return result;
    	
    }
    private BusinessException getBusinessException(Throwable e) throws BusinessException {
        if (e == null) {
            return null;
        }
        if (e instanceof BusinessException) {
            BusinessException e1 = (BusinessException) e;
            log.info("*********************************M1登陆异常：【错误代码】  " + e1.getCode() + "    【错误信息】   "
                    + e1.getMessage());
            String be1 = e1.getMessage().replace("<strong>", "");
            be1 = be1.replace("</strong>", "");
            throw MAppContextUtils.getException(MErrorConstants.C_iLogin_Tip_Exception + "", be1);
        } else {
            return getBusinessException(e.getCause());
        }
    }

    @Override
    public MBoolean transLogout(String token) throws BusinessException {
        MBoolean result = new MBoolean();
        
        client.remove(AppContext.currentUserId());
        bindedMap.remove(AppContext.currentUserId());
        sessionMapper.remove(AppContext.currentUserLoginName());
        HttpServletRequest request = AppContext.getRawRequest();
        HttpServletResponse response = AppContext.getRawResponse();
        HttpSession session = AppContext.getRawSession();

        String ticket = (String) session.getAttribute(CMPAuthenticationContants.TICKET);
        if (StringUtils.isNotBlank(ticket)) {
            ssoLogout.logout(ticket);
        }

        loginControl.transDoLogout(request, session, response);
        return result;
    }

    /**
     * 获取平台登录管理器
     * 
     * @return 返回平台登录管理器
     */
    public LoginControl getLoginControl() {
        return loginControl;
    }

    @Override
    public MBoolean registerPushServiceByToken(long memberID, String token, String protocolType)
            throws BusinessException {
        MBoolean result = new MBoolean();
        log.info(token);
        if (protocolType == null || orgManager.getMemberById(memberID) == null || Strings.isBlank(token)) {
            result.setValue(false);
        } else if (MConstant.C_iMessageClientProtocolType_Android.equals(protocolType)
                || MConstant.C_iMessageClientProtocolType_IPad.equals(protocolType)
                || MConstant.C_iMessageClientProtocolType_IPadInHouse.equals(protocolType)
                || MConstant.C_iMessageClientProtocolType_IPhone.equals(protocolType)
                || MConstant.C_iMessageClientProtocolType_IPhoneInHouse.equals(protocolType)) {
            MPushMessageListItem item = new MPushMessageListItem();
            item.setMessageCategory(1);
            MPushOperateMessageListItem operateItem = new MPushOperateMessageListItem();
            operateItem.setOperateType(1);
            operateItem.setProtocolType(protocolType);
        	token =token  +"|" + MAppContextUtils.getServerIdentifier();
            operateItem.setToken(token);
            operateItem.setMessageType(2);
            operateItem.setMemberID(memberID + "");
            item.setPushMessageItem(operateItem);
            MMessageCache.add(item);
            MMessageConfig config = mMessageManager.getMessagePushConfig(memberID);
            if (config == null) {
                MMessageUtils.registerUCService(protocolType, token, memberID, true);
            } else {
                String startPushTime = config.getPromptConfig().getStartPushTime();
                String endPushTime = config.getPromptConfig().getEndPushTime();
                Integer recevieMessage = config.getPromptConfig().getRecevieMessage();
                boolean recevie = false;
                if (recevieMessage == 1) {
                    if (MMessageEventListener.checkMessageByPushTime(startPushTime, endPushTime)) {
                        MUserMessagePushConfig userConfig = config.getmUserMessagePushConfig();
                        if (userConfig == null
                                || userConfig.getmOnlineMessagePushConfig() == null
                                || userConfig.getmOnlineMessagePushConfig().getPersonalOnlineMessage() == null
                                || userConfig.getmOnlineMessagePushConfig().getPersonalOnlineMessage()
                                        .isShowHomeScreen()) {
                            recevie = true;
                        }
                    }
                }
                MMessageUtils.registerUCService(protocolType, token, memberID, recevie);
            }
            client.put(memberID, token + "|" + protocolType);
            result.setValue(true);
        } else {
            result.setValue(false);
        }

        return result;
    }

    @Override
    public MBoolean unregisterPushServiceByToken(String token) {
        MBoolean result = new MBoolean();
        String indentifier = MAppContextUtils.getServerIdentifier();
        if(token == null) {
        	return result;
        }
        
        
        if(!token.contains(indentifier)){
        	token =token  +"|" + MAppContextUtils.getServerIdentifier();
        }
        MPushMessageListItem item = new MPushMessageListItem();
        item.setMessageCategory(1);
        MPushOperateMessageListItem operateItem = new MPushOperateMessageListItem();
        operateItem.setOperateType(2);
        operateItem.setToken(token);
        item.setPushMessageItem(operateItem);
        MMessageCache.add(item);
     //   MMessageUtils.registerUCService("", token, AppContext.currentUserId(), false);
        return result;
    }

    @Override
    public MLoginResult changeLoginAccount(long accountID) throws BusinessException {
      
    	MLoginResult result = new MLoginResult();
    	try{
    		MProductManager mproductManager = (MProductManager) AppContext.getBean("mProductManager");
    		Integer permissionType = mproductManager.getPermissionType();
    		if(permissionType == 2) {
	    		boolean   isMaxLogin =  OnlineRecorder.isExceedMaxLoginNumberM1InAccount(accountID);
	    		if(isMaxLogin) {
	    			V3xOrgAccount account = orgManager.getAccountById(accountID);
	    			throw new BusinessException(ResourceUtil.getString("login.label.ErrorCode.31", account.getShortName()));
	    		}
    		}
	        loginControl.transChangeLoginAccount(accountID);
	        User user = AppContext.getCurrentUser();
	        MOrgMember member = MOrganizationUtils.getConcurrentMember(user.getId(), accountID);
	        result.setCurrentUser(member);
	        result.setResourceList(null); // TODO 由于资源这块服务器端还未最终确定所以暂不设置
	        result.setGroupVer(SystemProperties.getInstance().getProperty("org.isGroupVer").equals("true"));
	        result  = initMPlugin(result);
    	}catch(Throwable e){
    		log.info(" change account failed !!!" );
    		this.getBusinessException(e);
    	}
        return result;
    }

    /**
     * 设置平台登录管理器
     * 
     * @param loginControl
     *            登录平台管理器
     */
    public void setLoginControl(LoginControl loginControl) {
        this.loginControl = loginControl;
    }

    /**
     * 获取平台组织机构管理器
     * 
     * @return 返回平台组织机构管理器
     */
    public MOrganizationManager getmOrgManager() {
        return mOrgManager;
    }

    /**
     * 设置平台组织机构管理器
     * 
     * @param mOrgManager
     *            设置平台组织机构管理器
     */
    public void setmOrgManager(MOrganizationManager mOrgManager) {
        this.mOrgManager = mOrgManager;
    }

    /**
     * @return mProductManager
     */
    public MProductManager getmProductManager() {
        return mProductManager;
    }

    /**
     * @param mProductManager
     */
    public void setmProductManager(MProductManager mProductManager) {
        this.mProductManager = mProductManager;
    }

    /**
     * @return mobileAuthService
     */
    public MobileAuthService getMobileAuthService() {
        return mobileAuthService;
    }

    /**
     * @param mobileAuthService
     */
    public void setMobileAuthService(MobileAuthService mobileAuthService) {
        this.mobileAuthService = mobileAuthService;
    }

    /**
     * 获取平台组织机构管理器
     * 
     * @return 返回平台组织机构管理器
     */
    public OrgManager getOrgManager() {
        return orgManager;
    }

    /**
     * 设置平台组织机构管理器
     * 
     * @param orgManager
     *            平台组织机构管理器
     */
    public void setOrgManager(OrgManager orgManager) {
        this.orgManager = orgManager;
    }

    /**
     * 设置消息设置管理器
     * 
     * @param mMessageManager
     *            消息设置管理器
     */
    public void setmMessageManager(MMessageManager mMessageManager) {
        this.mMessageManager = mMessageManager;
    }

    public void setmClientBindService(MClientBindService mClientBindService) {
        this.mClientBindService = mClientBindService;
    }

    public UserMapperDao getUserMapperDao() {
        return userMapperDao;
    }

    public void setUserMapperDao(UserMapperDao userMapperDao) {
        this.userMapperDao = userMapperDao;
    }
    
    public void setSsoLogout(ICMPSSOLogout ssoLogout) {
        this.ssoLogout = ssoLogout;
    }
    public CustomizeManager getCustomizeManager() {
        return customizeManager;
    }
    public void setCustomizeManager(CustomizeManager customizeManager) {
        this.customizeManager = customizeManager;
    }
	public MDidicarManager getmDidicarManager() {
		return mDidicarManager;
	}
	public void setmDidicarManager(MDidicarManager mDidicarManager) {
		this.mDidicarManager = mDidicarManager;
	}
    
	/**
	 * get请求，参数拼接在地址上
	 * @param url 请求地址加参数
	 * @return 响应
	 */
	public String get(String url){
	     String result = null;
	     RequestConfig requestConfig = RequestConfig.custom()
	    		 .setConnectTimeout(90000)
	    		 .setConnectionRequestTimeout(90000)
	    		 .setSocketTimeout(90000).build();
	     CloseableHttpClient httpClient = HttpClients.custom()
	    		    .setDefaultRequestConfig(requestConfig)
	    		    .build();
	     HttpGet get = new HttpGet(url);
	     CloseableHttpResponse response = null;
	     try {
	          response = httpClient.execute(get);
	          if(response != null && response.getStatusLine().getStatusCode() == 200){
	               HttpEntity entity = response.getEntity();
	               result = entityToString(entity);
	          }
	          return result;
	     } catch (IOException e) {
	          e.printStackTrace();
	          eRrorMessage=e.toString();
	          log.error(e.toString()+"访问品高的url:"+url);
	     }finally {
	          try {
	              httpClient.close();
	              if(response != null){
	                     response.close();
	              }
	          } catch (IOException e) {
	              e.printStackTrace();
              }
	      }
	      return null;
	}
	
	private String entityToString(HttpEntity entity) throws IOException {
		 String result = null;
		 if(entity != null){
		       long lenth = entity.getContentLength();
		       if(lenth != -1 && lenth < 2048){
		           result = EntityUtils.toString(entity,"UTF-8");
		       }else {
		           InputStreamReader reader1 = new InputStreamReader(entity.getContent(), "UTF-8");
		           CharArrayBuffer buffer = new CharArrayBuffer(2048);
		           char[] tmp = new char[1024];
		           int l;
		           while((l = reader1.read(tmp)) != -1) {
		                buffer.append(tmp, 0, l);
		           }
		           result = buffer.toString();
		       }
		 }
		 return result;
	}
}
