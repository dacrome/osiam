package de.osiam.client;


import com.github.springtestdbunit.DbUnitTestExecutionListener;
import com.github.springtestdbunit.annotation.DatabaseSetup;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.SerializationConfig;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.osiam.client.connector.OsiamConnector;
import org.osiam.client.exception.ConflictException;
import org.osiam.client.oauth.GrantType;
import org.osiam.client.update.UpdateUser;
import org.osiam.resources.scim.Address;
import org.osiam.resources.scim.MultiValuedAttribute;
import org.osiam.resources.scim.Name;
import org.osiam.resources.scim.User;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import static junit.framework.Assert.assertNotSame;
import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("/context.xml")
@TestExecutionListeners({DependencyInjectionTestExecutionListener.class,
        DbUnitTestExecutionListener.class})
@DatabaseSetup("/database_seed.xml")
public class UpdateUserIT extends AbstractIntegrationTestBase{

    private UUID idExisitngUser = UUID.fromString("7d33bcbe-a54c-43d8-867e-f6146164941e");
    private UpdateUser updateUSer;
    private User returnUser;
    private User originalUser;
    private static String IRRELEVANT = "Irrelevant";

    @Test
    public void delete_multivalue_attributes(){
    	try{
	    	getOriginalUser("dma");
	        createUpdateUserWithMultiDeleteFields();
	        updateUser();
	        assertTrue(isValuePartOfMultivalueList(originalUser.getEmails(), "hsimpson@atom-example.com"));
	        assertFalse(isValuePartOfMultivalueList(returnUser.getEmails(), "hsimpson@atom-example.com"));
	        assertTrue(isValuePartOfMultivalueList(originalUser.getPhoneNumbers(), "0245817964"));
	        assertFalse(isValuePartOfMultivalueList(returnUser.getPhoneNumbers(), "0245817964"));
	       // assertTrue(isValuePartOfMultivalueList(ORIGINAL_USER.getEntitlements(), "right2"));TODO at the second run it will fail
	       // assertFalse(isValuePartOfMultivalueList(RETURN_USER.getEntitlements(), "right2"));TODO at the second run it will fail
	        //assertTrue(isValuePartOfMultivalueList(ORIGINAL_USER.getGroups(), "d30a77eb-d7cf-4cd1-9fb3-cc640ef09578"));TODO Gruppen werden nicht gespeicher
	        //assertFalse(isValuePartOfMultivalueList(RETURN_USER.getGroups(), "d30a77eb-d7cf-4cd1-9fb3-cc640ef09578")); TODO Gruppen werden nicht gespeicher
	        assertTrue(isValuePartOfMultivalueList(originalUser.getIms(), "ims01"));
	        assertFalse(isValuePartOfMultivalueList(returnUser.getIms(), "ims01"));
	        assertTrue(isValuePartOfMultivalueList(originalUser.getPhotos(), "photo01.jpg"));
	        assertFalse(isValuePartOfMultivalueList(returnUser.getPhotos(), "photo01.jpg"));
	        assertTrue(isValuePartOfMultivalueList(originalUser.getRoles(), "role01"));
	        assertFalse(isValuePartOfMultivalueList(returnUser.getRoles(), "role01"));
	        //assertTrue(isValuePartOfMultivalueList(ORIGINAL_USER.getX509Certificates(), "certificate01"));//TODO at the second run it will fail
	        //assertFalse(isValuePartOfMultivalueList(RETURN_USER.getX509Certificates(), "certificate01"));//TODO at the second run it will fail
    	}finally{
    		oConnector.deleteUser(idExisitngUser, accessToken);
    	}
    }
    
    @Test
    public void delete_all_multivalue_attributes(){
    	try{
	    	getOriginalUser("dama");
	        createUpdateUserWithMultiAllDeleteFields();
	        updateUser();
	        assertNotNull(originalUser.getEmails());
	        assertNull(returnUser.getEmails());
	        assertNull(returnUser.getAddresses());
	        //assertNull(RETURN_USER.getEntitlements());TODO at the second run it will fail
	        assertNull(returnUser.getGroups());//TODO da Gruppen nicht gespeichert werden sind sie immer null
	        assertNull(returnUser.getIms());
	        assertNull(returnUser.getPhoneNumbers());
	        assertNull(returnUser.getPhotos());
	        assertNull(returnUser.getRoles());
	        assertNull(returnUser.getX509Certificates());
    	}finally{
    		oConnector.deleteUser(idExisitngUser, accessToken);
    	}
    }
    
    @Test
    public void delete_multivalue_attributes_which_is_not_available(){
    	try{
	    	getOriginalUser("dma");
	    	createUpdateUserWithWrongEmail();
	        updateUser();
    	}finally{
    		oConnector.deleteUser(idExisitngUser, accessToken);
    	}
    }
    
    @Test
    public void add_multivalue_attributes(){
    	try{
	    	getOriginalUser("ama");
	    	createUpdateUserWithMultiAddFields();
	    	updateUser();
	    	assertEquals(originalUser.getPhoneNumbers().size() + 1, returnUser.getPhoneNumbers().size());
	    	assertTrue(isValuePartOfMultivalueList(returnUser.getPhoneNumbers(), "99999999991"));
	    	//assertEquals(ORIGINAL_USER.getEmails().size() + 1, RETURN_USER.getEmails().size());TODO funktioniert nicht. Eine mailadresse wird von server gelöscht
	    	assertTrue(isValuePartOfMultivalueList(returnUser.getEmails(), "mac@muster.de"));
	    	//assertEquals(ORIGINAL_USER.getAddresses().size() + 1, RETURN_USER.getAddresses().size());TODO neue Addresse löscht zuerst die alten
	    	getAddress(returnUser.getAddresses(), "new Address");
	    	//assertEquals(ORIGINAL_USER.getEntitlements().size() + 1, RETURN_USER.getEntitlements().size());TODO at the second run it will fail
	    	//assertTrue(isValuePartOfMultivalueList(RETURN_USER.getEntitlements(), "right3"));TODO at the second run it will fail
	    	//assertEquals(ORIGINAL_USER.getGroups().size() + 1, RETURN_USER.getGroups().size());TODO gruppen werden aktuell nicht gespeichert
	    	//assertTrue(isValuePartOfMultivalueList(RETURN_USER.getGroups(), "d30a77eb-d7cf-4cd1-9fb3-cc640ef09578"));TODO gruppen werden aktuell nicht gespeichert
	    	assertEquals(originalUser.getIms().size() + 1, returnUser.getIms().size());
	    	//assertTrue(isValuePartOfMultivalueList(RETURN_USER.getIms(), "ims03"));//TODO der type wird nicht geändert
	    	assertEquals(originalUser.getPhotos().size() + 1, returnUser.getPhotos().size());
	    	assertTrue(isValuePartOfMultivalueList(returnUser.getPhotos(), "photo03.jpg"));
	    	assertEquals(originalUser.getRoles().size() + 1, returnUser.getRoles().size());
	    	assertTrue(isValuePartOfMultivalueList(returnUser.getRoles(), "role03"));
	    	//assertEquals(ORIGINAL_USER.getX509Certificates().size() + 1, RETURN_USER.getX509Certificates().size());//TODO at the second run it will fail
	    	//assertTrue(isValuePartOfMultivalueList(RETURN_USER.getX509Certificates(), "certificate03"));//TODO at the second run it will fail
    	}finally{
    		oConnector.deleteUser(idExisitngUser, accessToken);
    	}
    }
    
    @Test
    public void update_multivalue_attributes(){
    	try{
	    	getOriginalUser("uma");
	    	createUpdateUserWithMultiUpdateFields();
	    	updateUser();
	    	//phonenumber
	    	MultiValuedAttribute multi = getSingleMultiValueAttribute(returnUser.getPhoneNumbers(), "+497845/1157");
	    	//assertFalse(multi.isPrimary());TODO primary wird beim telefon nicht gesetzt
	    	multi = getSingleMultiValueAttribute(returnUser.getPhoneNumbers(), "0245817964");
	    	//assertTrue(multi.isPrimary());TODO primary wird beim telefon nicht gesetzt
	    	//assertEquals("other", multi.getType());TODO der type wird nicht geändert
	    	//email
	    	//MultiValuedAttribute multi = getSingleMultiValueAttribute(RETURN_USER.getEmails(), "hsimpson@atom-example.com");
	    	//assertFalse(multi.isPrimary());//TODO die atomadresse wird gelöscht und die andere wird nicht abgedatet
	    	//multi = getSingleMultiValueAttribute(RETURN_USER.getEmails(), "hsimpson@home-example.com");
	    	//assertTrue(multi.isPrimary());
	    	//assertEquals("other", multi.getType());
	    	multi = getSingleMultiValueAttribute(returnUser.getIms(), "ims01");
	    	//assertEquals("icq", multi.getType());//TODO der type wird nicht upgedatet
	    	multi = getSingleMultiValueAttribute(returnUser.getPhotos(), "photo01.jpg");
	    	//assertEquals("photo", multi.getType());//TODO der type wird nicht upgedatet
	    	//multi = getSingleMultiValueAttribute(RETURN_USER.getRoles(), "role01");//TODO der type wird nicht gespeichert und kann somit nicht geändert werden
	    	//assertEquals("other", multi.getType());//TODO der type wird nicht gespeichert und kann somit nicht geändert werden
	    	//multi = getSingleMultiValueAttribute(RETURN_USER.getGroups(), "69e1a5dc-89be-4343-976c-b5541af249f4"); //TODO gruppen werden nicht angelegt
	    	//assertEquals("indirect", multi.getType());
    	}finally{
    		oConnector.deleteUser(idExisitngUser, accessToken);
    	}
    }
    
	@Test
    public void update_all_single_values(){
		try{
	        getOriginalUser("uasv");
	        createUpdateUserWithUpdateFields();
	        updateUser();
	        assertNotEquals(originalUser.getUserName(), returnUser.getUserName());
	        assertNotEquals(originalUser.getNickName(), returnUser.getNickName());
	        assertNotEquals(originalUser.isActive(), returnUser.isActive());
	        assertNotEquals(originalUser.getDisplayName(), returnUser.getDisplayName());
	        assertNotEquals(originalUser.getExternalId(), returnUser.getExternalId());
	        assertNotEquals(originalUser.getLocale(), returnUser.getLocale());
	        assertNotEquals(originalUser.getPreferredLanguage(), returnUser.getPreferredLanguage());
	        assertNotEquals(originalUser.getProfileUrl(), returnUser.getProfileUrl());
	        assertNotEquals(originalUser.getTimezone(), returnUser.getTimezone());
	        assertNotEquals(originalUser.getTitle(), returnUser.getTitle());
	        assertNotEquals(originalUser.getUserType(), returnUser.getUserType());
	        assertNotEquals(originalUser.getName().getFamilyName(), returnUser.getName().getFamilyName());
	        assertNotEquals(originalUser.getExternalId(), returnUser.getExternalId());
		}finally{
    		oConnector.deleteUser(idExisitngUser, accessToken);
    	}
    }
		
	@Test
    public void delete_all_single_values(){
		try{
			getOriginalUser("desv");
	        createUpdateUserWithDeleteFields();
	        updateUser();
	        assertNull(returnUser.getNickName());
	        assertNull(returnUser.getDisplayName());
	        assertNull(returnUser.getLocale());
	        assertNull(returnUser.getPreferredLanguage());
	        assertNull(returnUser.getProfileUrl());
	        assertNull(returnUser.getTimezone());
	        assertNull(returnUser.getTitle());
	        assertNull(returnUser.getUserType());
	        assertNull(returnUser.getName());
	        assertNull(returnUser.getExternalId());
		}finally{
    		oConnector.deleteUser(idExisitngUser, accessToken);
    	}
    }
	
	@Test
	public void update_password() {
		try{
			getOriginalUser("uasv");
	        createUpdateUserWithUpdateFields();
	        updateUser();
	        makeNewConnectionWithNewPassword();
		}finally{
    		oConnector.deleteUser(idExisitngUser, accessToken);
    	}
	}
	
	@Test
	public void update_attributes_doesnt_change_the_password() {
		try{
			getOriginalUser("uadctp");
	        createUpdateUserWithUpdateFieldsWithoutPassword();
	        updateUser();
	        makeNewConnection();
		}finally{
    		oConnector.deleteUser(idExisitngUser, accessToken);
    	}
	}
	
	@Test
	public void change_one_field_and_other_attributes_are_the_same(){
		try{
			getOriginalUser("cnaoaats");
			createUpdateUserWithJustOtherNickname();
			updateUser();
	        assertNotEquals(originalUser.getNickName(), returnUser.getNickName());
	        assertEquals(originalUser.isActive(), returnUser.isActive());
	        assertEquals(originalUser.getDisplayName(), returnUser.getDisplayName());
	        assertEquals(originalUser.getExternalId(), returnUser.getExternalId());
	        assertEquals(originalUser.getLocale(), returnUser.getLocale());
	        assertEquals(originalUser.getPreferredLanguage(), returnUser.getPreferredLanguage());
	        assertEquals(originalUser.getProfileUrl(), returnUser.getProfileUrl());
	        assertEquals(originalUser.getTimezone(), returnUser.getTimezone());
	        assertEquals(originalUser.getTitle(), returnUser.getTitle());
	        assertEquals(originalUser.getUserType(), returnUser.getUserType());
	        assertEquals(originalUser.getName().getFamilyName(), returnUser.getName().getFamilyName());
		}finally{
    		oConnector.deleteUser(idExisitngUser, accessToken);
    	}
	}
	
	@Test (expected = ConflictException.class)
	public void invalid_email_type_in_update_User_is_thrown_probably(){
		try{
			getOriginalUser("ietiuuitp");
			createUpdateUserWithInvalidEmailType();
			updateUser();
			fail("exception expected");
		}finally{
    		oConnector.deleteUser(idExisitngUser, accessToken);
    	}
	}
	
	@Test (expected = ConflictException.class)
	public void username_is_set_no_empty_string_is_thrown_probably(){
		try{
			getOriginalUser("ietiuuitp");
			createUpdateUserWithEmptyUserName();
			updateUser();
			fail("exception expected");
		}finally{
    		oConnector.deleteUser(idExisitngUser, accessToken);
    	}
	}
	
	private String getUpdateUser(){
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure( SerializationConfig.Feature.FAIL_ON_EMPTY_BEANS, false );
        String userAsString = null;
        try {
            userAsString = mapper.writeValueAsString(updateUSer.getUserToUpdate());
        } catch (IOException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
        return userAsString;
	}

	public boolean isValuePartOfMultivalueList(List<MultiValuedAttribute> list, String value){
		if(list != null){
			for (MultiValuedAttribute actAttribute : list) {
				if(actAttribute.getValue().equals(value)){
					return true;
				}
			}
		}
		return false;
	}
	
	public MultiValuedAttribute getSingleMultiValueAttribute(List<MultiValuedAttribute> multiValues, Object value){
		if(multiValues != null){
			for (MultiValuedAttribute actMultiValuedAttribute : multiValues) {
				if(actMultiValuedAttribute.getValue().equals(value)){
					return actMultiValuedAttribute;
				}
			}
		}
		fail("The value " + value + " could not be found");
		return null; //Can't be reached
	}
	
    public void getOriginalUser(String userName){
        User.Builder userBuilder = new User.Builder(userName);
        
        MultiValuedAttribute email01 = new MultiValuedAttribute.Builder().setValue("hsimpson@atom-example.com").setType("work").setPrimary(true).build();
        MultiValuedAttribute email02 = new MultiValuedAttribute.Builder().setValue("hsimpson@home-example.com").setType("work").build();
        List<MultiValuedAttribute> emails = new ArrayList<>();
        emails.add(email01);
        emails.add(email02);        
        
        MultiValuedAttribute phoneNumber01 = new MultiValuedAttribute.Builder().setValue("+497845/1157").setType("work").setPrimary(true).build();
        MultiValuedAttribute phoneNumber02 = new MultiValuedAttribute.Builder().setValue("0245817964").setType("home").build();
        List<MultiValuedAttribute> phoneNumbers = new ArrayList<>();
        phoneNumbers.add(phoneNumber01);
        phoneNumbers.add(phoneNumber02);
        
        Address simpleAddress01 = new Address.Builder().setCountry("de").setFormatted("formated address").setLocality("Berlin").setPostalCode("111111").build();
        Address simpleAddress02 = new Address.Builder().setCountry("en").setFormatted("address formated").setLocality("New York").setPostalCode("123456").build();
        List<Address> addresses = new ArrayList<>();
        addresses.add(simpleAddress01);
        addresses .add(simpleAddress02);   
        
        MultiValuedAttribute entitlement01 = new MultiValuedAttribute.Builder().setValue("right1").build();
        MultiValuedAttribute entitlement02 = new MultiValuedAttribute.Builder().setValue("right2").build();
        List<MultiValuedAttribute> entitlements = new ArrayList<>();
        entitlements.add(entitlement01);
        entitlements.add(entitlement02);
        
        MultiValuedAttribute group01 = new MultiValuedAttribute.Builder().setValue("69e1a5dc-89be-4343-976c-b5541af249f4").setType("direct").build();
        MultiValuedAttribute group02 = new MultiValuedAttribute.Builder().setValue("d30a77eb-d7cf-4cd1-9fb3-cc640ef09578").build();
        List<MultiValuedAttribute> groups = new ArrayList<>();
        groups.add(group01);
        groups.add(group02);
        
        MultiValuedAttribute ims01 = new MultiValuedAttribute.Builder().setValue("ims01").setType("skype").build();
        MultiValuedAttribute ims02 = new MultiValuedAttribute.Builder().setValue("ims02").build();
        List<MultiValuedAttribute> ims = new ArrayList<>();
        ims.add(ims01);
        ims.add(ims02);
        
        MultiValuedAttribute photo01 = new MultiValuedAttribute.Builder().setValue("photo01.jpg").setType("thumbnail").build();
        MultiValuedAttribute photo02 = new MultiValuedAttribute.Builder().setValue("photo02.jpg").build();
        List<MultiValuedAttribute> photos = new ArrayList<>();
        photos.add(photo01);
        photos.add(photo02);
        
        MultiValuedAttribute role01 = new MultiValuedAttribute.Builder().setValue("role01").setType("some").build();
        MultiValuedAttribute role02 = new MultiValuedAttribute.Builder().setValue("role02").build();
        List<MultiValuedAttribute> roles = new ArrayList<>();
        roles.add(role01);
        roles.add(role02);
        
        MultiValuedAttribute certificate01 = new MultiValuedAttribute.Builder().setValue("certificate01").setType("some").build();
        MultiValuedAttribute certificate02 = new MultiValuedAttribute.Builder().setValue("certificate02").build();
        List<MultiValuedAttribute> certificates = new ArrayList<>();
        certificates.add(certificate01);
        certificates.add(certificate02);
        
        Name name = new Name.Builder().setFamilyName("familiyName").setFormatted("formatted Name").setGivenName("givenName").build();

        		userBuilder.setNickName("irgendwas")
        			.setEmails(emails)
        			.setPhoneNumbers(phoneNumbers)
        			.setActive(false)
        			.setDisplayName("irgendwas")
        			.setLocale("de")
        			.setPassword("geheim")
        			.setPreferredLanguage("de")
        			.setProfileUrl("irgendwas")
        			.setTimezone("irgendwas")
        			.setTitle("irgendwas")
        			.setUserType("irgendwas")
        			.setAddresses(addresses)
        			.setGroups(groups)
        			.setIms(ims)
        			.setPhotos(photos)
        			.setRoles(roles)
        			.setName(name)
        			.setExternalId("irgendwas")
        			//.setX509Certificates(certificates)
        			//.setEntitlements(entitlements)TODO at the second run it will fail
        			;
        User newUser = userBuilder.build(); 
        
        originalUser = oConnector.createUser(newUser, accessToken);
        idExisitngUser = UUID.fromString(originalUser.getId());
    }

    private void createUpdateUserWithUpdateFields(){
    	Name newName = new Name.Builder().setFamilyName("newFamilyName").build();
        updateUSer = new UpdateUser.Builder(IRRELEVANT)
        					.updateNickName(IRRELEVANT)
        					.updateExternalId(IRRELEVANT)
        					.updateDisplayName(IRRELEVANT)
        					.updatePassword(IRRELEVANT)
        					.updateLocal(IRRELEVANT)
        					.updatePreferredLanguage(IRRELEVANT)
        					.updateProfileUrl(IRRELEVANT)
        					.updateTimezone(IRRELEVANT)
        					.updateTitle(IRRELEVANT)
        					.updateUserType(IRRELEVANT)
        					.updateExternalId(IRRELEVANT)
        					.updateName(newName)
        					.setActive(true).build();
    }
    
    private void createUpdateUserWithUpdateFieldsWithoutPassword(){
    	Name newName = new Name.Builder().setFamilyName("newFamilyName").build();
        updateUSer = new UpdateUser.Builder(UUID.randomUUID().toString())
        					.updateNickName(IRRELEVANT)
        					.updateExternalId(IRRELEVANT)
        					.updateDisplayName(IRRELEVANT)
        					.updateLocal(IRRELEVANT)
        					.updatePreferredLanguage(IRRELEVANT)
        					.updateProfileUrl(IRRELEVANT)
        					.updateTimezone(IRRELEVANT)
        					.updateTitle(IRRELEVANT)
        					.updateUserType(IRRELEVANT)
        					.updateName(newName)
        					.setActive(true).build();
    }
    
    private void createUpdateUserWithJustOtherNickname(){
        updateUSer = new UpdateUser.Builder(IRRELEVANT)//TODO bug in Server
		.updateNickName(IRRELEVANT)
		.build();
    }
    
    private void createUpdateUserWithInvalidEmailType(){
    	MultiValuedAttribute email = new MultiValuedAttribute.Builder().setValue("some@thing.com").setType("wrong").build();
        updateUSer = new UpdateUser.Builder(IRRELEVANT)//TODO bug in Server
		.addOrUpdateEmail(email)
		.build();
    }
    
    private void createUpdateUserWithEmptyUserName(){
        updateUSer = new UpdateUser.Builder("")
		.build();
    }
    
    private void createUpdateUserWithMultiUpdateFields(){

    	MultiValuedAttribute email = new MultiValuedAttribute.Builder()
    					.setValue("hsimpson@home-example.com").setType("other").setPrimary(true).build();
    	MultiValuedAttribute phoneNumber = new MultiValuedAttribute.Builder().setValue("0245817964").setType("other")
    			.setPrimary(true).build(); //Now the other should not be primary anymore
    	MultiValuedAttribute ims = new MultiValuedAttribute.Builder().setValue("ims01").setType("icq").build();
    	MultiValuedAttribute photo = new MultiValuedAttribute.Builder().setValue("photo01.jpg").setType("photo").build(); 
    	MultiValuedAttribute role = new MultiValuedAttribute.Builder().setValue("role01").setType("other").build();
    	MultiValuedAttribute group = new MultiValuedAttribute.Builder().setValue("69e1a5dc-89be-4343-976c-b5541af249f4").setType("indirect").build();
    	new MultiValuedAttribute.Builder().setValue("test").setType("other").build();
    	
    	updateUSer = new UpdateUser.Builder(IRRELEVANT) //TODO username nur solange bug im server existiert
        					.addOrUpdateEmail(email)
        					.addOrUpdatesPhoneNumber(phoneNumber)
        					.addOrUpdatesPhoto(photo)
        					.addOrUpdatesIms(ims)
        					.addOrUpdateRole(role)
        					.addOrUpdateGroupMembership(group)
        					.build();
    }
    
    private void createUpdateUserWithDeleteFields(){
        updateUSer = new UpdateUser.Builder(IRRELEVANT) //TODO username nur solange bug im server existiert
        					.deleteDisplayName()
        					.deleteNickName()
        					.deleteLocal()
        					.deletePreferredLanguage()
        					.deleteProfileUrl()
        					.deleteTimezone()
        					.deleteTitle()
        					.deleteUserType()
        					.deleteName()
        					.deleteExternalId()
        					.build();
    }
    
    private void createUpdateUserWithMultiDeleteFields(){

    	updateUSer = new UpdateUser.Builder(IRRELEVANT) //TODO username nur solange bug im server existiert
        					.deleteEmail("hsimpson@atom-example.com")
        					//.deleteEntitlement("right2")TODO at the second run it will fail
        					.deleteGroup(UUID.fromString("d30a77eb-d7cf-4cd1-9fb3-cc640ef09578"))
        					.deleteIms("ims01")
        					.deletePhoneNumber("0245817964")
        					.deletePhoto("photo01.jpg")
        					.deleteRole("role01")
        					//.deleteX509Certificate("certificate01")
        					.build();
    }
    
    private void createUpdateUserWithWrongEmail(){

    	updateUSer = new UpdateUser.Builder(IRRELEVANT) //TODO username nur solange bug im server existiert
        					.deleteEmail("test@test.com")
        					.build();
    }
    
    private void createUpdateUserWithMultiAddFields(){

    	MultiValuedAttribute email = new MultiValuedAttribute.Builder()
    					.setValue("mac@muster.de").setType("home").build();
    	
    	MultiValuedAttribute phonenumber = new MultiValuedAttribute.Builder()
		.setValue("99999999991").setType("home").build();
    	
    	Address newSimpleAddress = new Address.Builder().setCountry("fr").setFormatted("new Address").setLocality("New City").setPostalCode("66666").build();
    	MultiValuedAttribute entitlement = new MultiValuedAttribute.Builder().setValue("right3").build();
    	MultiValuedAttribute ims = new MultiValuedAttribute.Builder().setValue("ims03").build();
    	MultiValuedAttribute photo = new MultiValuedAttribute.Builder().setValue("photo03.jpg").build();
    	MultiValuedAttribute role = new MultiValuedAttribute.Builder().setValue("role03").build();
    	MultiValuedAttribute certificate = new MultiValuedAttribute.Builder().setValue("certificate03").setType("some").build();
    	MultiValuedAttribute groupMembership = new MultiValuedAttribute.Builder().setValue("d30a77eb-d7cf-4cd1-9fb3-cc640ef09578").build();
    	
    	updateUSer = new UpdateUser.Builder(IRRELEVANT) //TODO username nur solange bug im server existiert
        					.addOrUpdateEmail(email)
        					.addOrUpdatesPhoneNumber(phonenumber)
        					.addAddress(newSimpleAddress)
        					//.addEntitlement(entitlement)//TODO at the second run it will fail
        					.addOrUpdateGroupMembership(groupMembership) //TODO Gruppen werden nicht gespeichert 
        					.addOrUpdatesIms(ims)
        					.addOrUpdatesPhoto(photo)
        					.addOrUpdateRole(role)
        					.addOrUpdateX509Certificate(certificate)//TODO at the second run it will fail
        					.build();
    }
    

    
    private void createUpdateUserWithMultiAllDeleteFields(){

    	updateUSer = new UpdateUser.Builder(IRRELEVANT) //TODO username nur solange bug im server existiert
        					.deleteEmails()
        					.deleteAddresses()
        					//.deleteEntitlements()TODO at the second run it will fail
        					.deleteGroups() //TODO Gruppen werden nicht gespeichert und können somit auch nicht gelöscht werden
        					.deleteIms()
        					.deletePhoneNumbers()
        					.deletePhotos()
        					.deleteRoles()
        					.deleteX509Certificates()
        					.build();
    }

    private void updateUser(){
       returnUser = oConnector.updateUser(idExisitngUser, updateUSer, accessToken);
    }

    
    private void makeNewConnectionWithNewPassword() {
    	OsiamConnector.Builder oConBuilder = new OsiamConnector.Builder(endpointAddress).
                setClientId(clientId).
                setClientSecret(clientSecret).
                setGrantType(GrantType.PASSWORD).
                setUsername(IRRELEVANT).
                setPassword(IRRELEVANT);
        oConnector = oConBuilder.build();
        oConnector.retrieveAccessToken();
    }
    
    private void makeNewConnection() {
    	OsiamConnector.Builder oConBuilder = new OsiamConnector.Builder(endpointAddress).
                setClientId(clientId).
                setClientSecret(clientSecret).
                setGrantType(GrantType.PASSWORD).
                setUsername("marissa").
                setPassword("koala");
        oConnector = oConBuilder.build();
        oConnector.retrieveAccessToken();
    }
    
	public Address getAddress(List<Address> addresses, String formated){
		if(addresses != null){
			for (Address actAddress : addresses) {
				if(actAddress.getFormatted().equals(formated)){
					return actAddress;
				}
			}
		}
		fail("The address with the formated part of " + formated + " could not be found");
		return null; //Can't be reached
	}

}
