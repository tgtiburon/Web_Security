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
        // load and parse savedVTID
       savedVTID = JSON.parse(localStorage.getItem("savedVTID"));
    
       console.log("savedVTID = " + savedVTID)
    }

    savedVTResults = localStorage.getItem("savedVTResults");
    //no savedVTResults
    if (!savedVTResults) {
        savedVTResults = [];
    }else {
        // load and parse savedVTResults
       let savedVTResults = JSON.parse(localStorage.getItem("savedVTResults"));
        console.log("savedVTResults = "  );
        console.log(savedVTResults);
        processVTData(savedVTResults);
    }
   // finalResultsObjArr
    finalResultsObjArr = localStorage.getItem("finalResultsObjArr");
    //no savedVTResults
    if (!finalResultsObjArr) {
        finalResultsObjArr = [];
    }else {
        // load and parse savedVTResults
       let finalResultsObjArr = JSON.parse(localStorage.getItem("savedVTResults"));
        console.log("finalResultsObjArr = "  );
        console.log(finalResultsObjArr);
        
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
    // debug info
    console.log(formData);
    console.log(myHeaders);
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
             
                savedVTID = data.data.id;
                  
                localStorage.setItem("savedVTID", JSON.stringify(savedVTID));
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
    console.log(myRequestURL);
    // try and fetch the analysis of the url
   fetch(myRequestURL, myRequestObject).then(function(response){ 
 
    console.log(response);
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
        console.log(response);
    });
   
}// end webSiteScan


/*  Function: processVTData
    => Takes the data from the analyze call at VT
    and puts it into easy to use objects or array??
    args: savedVTResults
    return: none
*/

processVTData = (savedVTResults) => {

  // debugger;
  savedVTResults = savedVTResults;

   // let tmpStr = savedVTResults.meta;
    console.log(savedVTResults.data.attributes.results);
    let tmpObj = savedVTResults.data.attributes.results
  

   let i = 0;
   let finalResultsObjArr = [];

   

    Object.values(tmpObj).forEach(val=> {


    
 // push the data into finalResultsObjArr for displaying results.
        finalResultsObjArr.push({engine:val.engine_name, verdict:val.category});
   

    
        i++;
    });
    console.log(finalResultsObjArr);
    // lets save it
    localStorage.setItem("finalResultsObjArr", JSON.stringify(finalResultsObjArr));

   

}

$("body").on("click", "#testButton", function() {
    console.log(this);
});



// Might use JQUERY instead
const buttonHandler = (event) => {
    console.log(event);
  
         
};

function linkScan(website) {
    urlScan = "4929f2c5-ed32-477f-b97e-bf05771c34a5";
};

button.addEventListener("submit", linkScan(website));
// Function calls
initialLoad();// Call this to start the website.