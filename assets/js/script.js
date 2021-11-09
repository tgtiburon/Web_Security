
console.log("script.js loaded!");


// Variables
const vTotalInfo = '8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a';
savedVTID = []; //Holds the saved ID from Virus Total 
savedVTResults = []; //Holds the results from the URL scan





// Functions

/*  Function: initialLoad() 
    => Called when the website loads to take care of any housekeeping issues.
    args: none
    return: none
*/

const initialLoad = () => {
    // load saved data so we don't use up api calls
    loadSavedData();


}//end initialLoad()

/*  Function: loadSavedData()
    => loads all saved Data
    args: none
    return: none
*/

let loadSavedData = function() {

    let savedVTID = localStorage.getItem("savedVTID");
    //no savedVTID make one
    if (!savedVTID) {
        savedVTID = [];
    } else {
        // load and parse savedVTID
       savedVTID = JSON.parse(localStorage.getItem("savedVTID"));
    
       console.log("analysisID = " + savedVTID)
    }
    
    //return savedVTID;
};

/*  Function: webSiteGetID 
    => fetches the special VirusTotal ID needed to run analyse
    args: none
    return: none
*/

const webSiteGetID  = () => {

    let myRequestURL = "https://www.virustotal.com/api/v3/urls";
   
    let formData = new FormData();
    formData.append('url', 'www.google.com');

    let myHeaders = new Headers();
    myHeaders = {"X-Apikey" : vTotalInfo };
    console.log(formData);
    console.log(myHeaders);
 
    myRequestObject = {
        method: 'POST',
        headers: myHeaders,
       
        body: formData,
        mode: 'cors'
           
    }

   fetch(myRequestURL, myRequestObject).then(function(response){ 
 
    console.log(response);
        if(response.ok) {
          
            response.json().then(function(data) {
             
                savedVTID = data.data.id;
                  
                localStorage.setItem("savedVTID", JSON.stringify(savedVTID));
                webSiteScan(savedVTID);
            
            });
        } else {
            console.log("WebsiteGetID failed to get an ID!");
        }
    });


};//End websiteGetID()


/*  Function: webSiteScan
    => Takes the VT url ID and sends it to get analyzed
    and saves the result to localStorage to cut down on API calls.
    args: savedVTID
    return: none
*/
const webSiteScan = (savedVTID) => {

    let myRequestURL = "https://www.virustotal.com/api/v3/analyses/" + savedVTID;

    let myHeaders = new Headers();
    myHeaders = {"X-Apikey" : vTotalInfo };
  
    myRequestObject = {
        method: 'GET',
        headers: myHeaders,
        mode: 'cors'
        
    }
    console.log(myRequestURL);

   fetch(myRequestURL, myRequestObject).then(function(response){ 
 
    console.log(response);
        if(response.ok) {
        
            response.json().then(function(data) {
           
                savedVTResults = data;
               
                localStorage.setItem("savedVTResults", JSON.stringify(savedVTResults));
            
            });

        } else {
            console.log("It failed!");
           
        }
        console.log(response);
    });
   
}// end webSiteScan


$("body").on("click", "#testButton", function() {
    console.log(this);
});



// Might use JQUERY instead
const buttonHandler = (event) => {
    console.log(event);
  
         
};




// Function calls


initialLoad();




// Listeners
document.addEventListener("click", buttonHandler);


