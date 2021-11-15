
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
    
    }

    savedVTResults = localStorage.getItem("savedVTResults");
    //no savedVTResults
    if (!savedVTResults) {
        savedVTResults = [];
    }else {
        // load and parse savedVTResults -- This is the saved results from virus
        // total after we sent it for analysis.
       let savedVTResults = JSON.parse(localStorage.getItem("savedVTResults"));
        processVTData(savedVTResults);
    }
 
    finalResultsObjArr = localStorage.getItem("finalResultsObjArr");
    //no savedVTResults
    if (!finalResultsObjArr) {
        finalResultsObjArr = [];
    }else {
        // load and parse savedVTResults
       let finalResultsObjArr = JSON.parse(localStorage.getItem("finalResultsObjArr"));
      // displayVTData(finalResultsObjArr);
       
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
    formData.append('url', 'malware.wicar.org');
    // set up the headers
    let myHeaders = new Headers();
    myHeaders = {"X-Apikey" : vTotalInfo };
   
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

    // try and fetch the analysis of the url
   fetch(myRequestURL, myRequestObject).then(function(response){ 
 
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
    });  
}// end webSiteScan



// Code to scan ny times technology articles
const storyScan = () => {

    tmpAPI = "A7QoqgMwCbe99GKVGJdTY3zisUsBXdAl";
  
    const url9 = "https://api.nytimes.com/svc/news/v3/content/all/technology.json?api-key="+tmpAPI;

   const options = {
     method: "GET",
     headers: {
       "Accept": "application/json"
     },
   };
   fetch(url9, options).then(
     response => {
       if (response.ok) {
         return response.json();
       }
       return response.text().then(err => {
         return Promise.reject({
           status: response.status,
           statusText: response.statusText,
           errorMessage: err,
         });
       });
     })
     .then(data => {
       console.log(data);
     })
     .catch(err => {
       console.error(err);
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
    // We are turning the results into a temporary object so we can 
    // use forEach to loop through it later.
    let tmpObj = savedVTResults.data.attributes.results
    // iterator for the Object loop
    let i = 0;
    let finalResultsObjArr = [];
    let dirtyResults = [];
    let totalClean = 0;
    let totalDirty = 0;
//debugger;
    // Using forEach to go through the object array so we can store the results in an easier format
    Object.values(tmpObj).forEach(val=> {

        // push the data into finalResultsObjArr for displaying results.
        finalResultsObjArr.push({engine:val.engine_name, verdict:val.result});

        // Lets analyze the data 
        if(val.result === "clean" || val.result === "unrated") {
            totalClean++
        } else {
            totalDirty++
            dirtyResults.push({engine:val.engine_name, verdict:val.result});

        }
       // console.log("val.result= " + val.result);
      //  console.log("totalClean= " + totalClean);
       // console.log("totalDirty= " + totalDirty);
        

        i++;
    });
    console.log(dirtyResults);




//SCAN SUMMARY LEFT COLUMN
let tmpObj2 =  savedVTResults.data.attributes.stats;
let objName1 = "";
let objName2 = "";
objName1 = $("<div>")
    .addClass("column is-2")
    .attr("id", "scan_summary");
$("#virusResults").append(objName1);
objName1 = $("<ul>")
    .addClass("column  ml-2 mt-4")
    .text("Scan Summary");

$("#scan_summary").append(objName1);
  
  objName2 = $("<li>").text("Harmless: " + tmpObj2.harmless);
  objName1.append(objName2);
  objName2 = $("<li>").text("Malicous: " + tmpObj2.malicious);
  objName1.append(objName2);
  objName2 = $("<li>").text("Suspicious: " + tmpObj2.suspicious);
  objName1.append(objName2);
  objName2 = $("<li>").text("Undetected: " + tmpObj2.undetected);
  objName1.append(objName2);


  // RIGHT COLUMN Flagged engines  make a div for it
  objName1 = $("<div>")
    .addClass("columns is-9 ml-2 mt-4 is-multiline")
    .attr("id", "card_holder");
  $("#virusResults").append(objName1);


  Object.values(dirtyResults).forEach(val=> {
    console.log(dirtyResults)

      //build a card for each one
      objName1 = $("<div>")
      .addClass("notification is-danger is-light is-2 p-1 m-1")
      .text(val.engine + ":  "+ val.verdict)
      
      .attr("card-color", "red");
    $("#card_holder").append(objName1);
  
//dirtyResults.push({engine:val.engine_name, verdict:val.result});




    i++;
});


    console.log(savedVTResults.data.attributes.stats.harmless);




    // Lets display the data
   




    console.log("totalClean= " + totalClean);
    console.log("totalDirty= " + totalDirty);

    // lets save the new object array.
    // saved as   Engine Name :  Result   
    localStorage.setItem("finalResultsObjArr", JSON.stringify(finalResultsObjArr));
}

/*  Function: displayVTData
    => Takes the data and displays it in 
    the Scan_Results div
    args: finalResultsObjArr
    return: none
*/

// displayVTData  = (finalResultsObjArr) => {

//     // don't do this
//     finalResultsObjArr = localStorage.getItem("finalResultsObjArr");
// debugger;
//     // find total non-clean
//     finalResultsObjArr = finalResultsObjArr;
    
//     let totalClean = 0;
//     let totalDirty = 0;

//     for (let i = 0; i < finalResultsObjArr.length; i++) {
//         const element = finalResultsObjArr[i];


//         if(finalResultsObjArr[i].verdict === "clean") {
//             totalClean = totalClean + 1;



//         } else {

            
//         }

        
//     }
  


    // Find total clean

    // Display non-clean


    //Display clean


//}
// Label the input button with id="inputButton" so
// it can be tied to this.
$("body").on("click", "#inputButton", function() {
    console.log(this);
});


// Function calls
initialLoad();// Call this to start the website.



