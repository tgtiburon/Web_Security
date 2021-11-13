
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
   // processVTData();


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
        // load and parse savedVTID  This is the ID returned
        // by virustotal when we send the url to it.
        // We use the ID by sending it to virustotal, which it uses to analyze the url.
       savedVTID = JSON.parse(localStorage.getItem("savedVTID"));
    
       //console.log("savedVTID = " + savedVTID)
    }

    savedVTResults = localStorage.getItem("savedVTResults");
    //no savedVTResults
    if (!savedVTResults) {
        savedVTResults = [];
    }else {
        // load and parse savedVTResults -- This is the saved results from virus
        // total after we sent it for analysis.
       let savedVTResults = JSON.parse(localStorage.getItem("savedVTResults"));
       // console.log("savedVTResults = "  );
      //  console.log(savedVTResults);
        processVTData(savedVTResults);
    }
   // finalResultsObjArr
    finalResultsObjArr = localStorage.getItem("finalResultsObjArr");
    //no savedVTResults
    if (!finalResultsObjArr) {
        finalResultsObjArr = [];
    }else {
        // load and parse savedVTResults
       let finalResultsObjArr = JSON.parse(localStorage.getItem("finalResultsObjArr"));
      //  console.log("finalResultsObjArr = "  );
       // console.log(finalResultsObjArr);
        
    }

   
     
};

/*  Function: webSiteGetID 
    => fetches the special VirusTotal ID needed to run analyse
    args: URL that needs it's unique ID
    return: none
*/

const webSiteGetID  = (/*url*/) => {

    // website we want to scan.  We will have input box later
    let myRequestURL = "https://www.virustotal.com/api/v3/urls";
   // need to submit as a FormData object
    let formData = new FormData();
    formData.append('url', 'www.google.com');
    // set up the headers
    let myHeaders = new Headers();
    myHeaders = {"X-Apikey" : vTotalInfo };
    //myHeaders = {"Content-Type" : "application/json", "API-Key" : yourVaribleForAPI};
    // debug info
    //console.log(formData);
    //console.log(myHeaders);
    //Create the myRequestObject
    myRequestObject = {
        method: 'POST',
        headers: myHeaders,
        body: formData,
        mode: 'cors' 
          
    }
   // Try and fetch the id of the website
   fetch(myRequestURL, myRequestObject).then(function(response){ 
 
    console.log(response);
        if(response.ok) {
          // it worked so save the id
            response.json().then(function(data) {

                // Virus total sends us the ID of the URL 
             
                savedVTID = data.data.id;
                  
                localStorage.setItem("savedVTID", JSON.stringify(savedVTID));
                // Now we send the special ID virus total sent us, back to them to analyze
                // I am not sure why they don't do it all in one step.  
                webSiteScan(savedVTID);
            
            });
        } else {
            //it failed
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
    // URL for requesting a scan of the URL with the special ID
    let myRequestURL = "https://www.virustotal.com/api/v3/analyses/" + savedVTID;
    // set up the header
    let myHeaders = new Headers();
    myHeaders = {"X-Apikey" : vTotalInfo };
    // create myRequestObject
    myRequestObject = {
        method: 'GET',
        headers: myHeaders,
        mode: 'cors'    
    }
    // for debugging
   // console.log(myRequestURL);
    // try and fetch the analysis of the url
   fetch(myRequestURL, myRequestObject).then(function(response){ 
 
    //console.log(response);
        if(response.ok) {
            // it worked parse and store the data
        
            response.json().then(function(data) {
           
                savedVTResults = data;
               
                localStorage.setItem("savedVTResults", JSON.stringify(savedVTResults));

                // Time to process all that data
                processVTData(savedVTResults);
            
            });

        } else {
            // it failed.
            console.log("It failed!");
           
        }
        //console.log(response);
    });
   
}// end webSiteScan


const urlScanIO = () => {

    // curl -H "Content-Type: application/json" -H "API-Key: 4929f2c5-ed32-477f-b97e-bf05771c34a5" "https://urlscan.io/user/quotas/"
    tmpAPI = "4929f2c5-ed32-477f-b97e-bf05771c34a5";
    // website we want to scan.  We will have input box later
    let myRequestURL = "https:urlscan.io/api/v1/scan/";

   // need to submit as a FormData object
    let formData = new FormData();
   // formData.append('url', 'www.google.com');
   // formData.append("visibility", "public");

    formData= {"url":"www.google.com", "visibility":"public"};
    // set up the headers
    let myHeaders = new Headers();

    myHeaders = { "Content-Type": "application/json","API-Key" : tmpAPI };
    //myHeaders = {"Content-Type" : "application/json", "API-Key" : yourVaribleForAPI};
    // debug info
    //console.log(formData);
    //console.log(myHeaders);
    //Create the myRequestObject
    console.log( formData);
    myRequestObject = {
        method: 'POST',
        headers:myHeaders,
        data: formData,
       // body:formData,
       // url: formData,
      // body: myRequestURL,
        mode: 'cors' 
          
    }
    console.log(myRequestObject);
   // Try and fetch the id of the website
   //fetch(myRequestURL, myRequestObject).then(function(response){ 
    fetch( myRequestURL, myRequestObject).then(function(response){ 
 
    console.log(response);
        if(response.ok) {
          // it worked so save the id
            response.json().then(function(data) {

                // Virus total sends us the ID of the URL 
                console.log("Got good response");
                console.log(data);
             
               // savedVTID = data.data.id;
                  
               // localStorage.setItem("savedVTID", JSON.stringify(savedVTID));
                // Now we send the special ID virus total sent us, back to them to analyze
                // I am not sure why they don't do it all in one step.  
               // webSiteScan(savedVTID);
            
            });
        } else {
            //it failed
            console.log("WebsiteGetID failed to get an ID!");
        }
    });




}
/*  Function: processVTData
    => Takes the data from the analyze call at VT
    and puts it into easy to use objects or array??
    args: savedVTResults
    return: none
*/

processVTData = (savedVTResults) => {

    // storing the savedVTResults sent to the function into a variable with 
    // the same name
    savedVTResults = savedVTResults;

    //console.log(savedVTResults.data.attributes.results);
    // We are turning the results into a temporary object so we can 
    // use forEach to loop through it later.
    let tmpObj = savedVTResults.data.attributes.results
  
    // iterator for the Object loop
   let i = 0;
   let finalResultsObjArr = [];

    // Using forEach to go through the object array so we can store the results in an easier format
    Object.values(tmpObj).forEach(val=> {

        // push the data into finalResultsObjArr for displaying results.
        finalResultsObjArr.push({engine:val.engine_name, verdict:val.result});
        i++;
    });

    //console.log(finalResultsObjArr);
    // lets save the new object array.
    // saved as   Engine Name :  Result   
    localStorage.setItem("finalResultsObjArr", JSON.stringify(finalResultsObjArr));

   

}
// Label the input button with id="inputButton" so
// it can be tied to this.
$("body").on("click", "#inputButton", function() {
    console.log(this);
});


// Function calls
initialLoad();// Call this to start the website.




// Listeners --We will probably use jquery so won't need them.



