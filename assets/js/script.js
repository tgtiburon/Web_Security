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
    
       console.log("savedVTID = " + savedVTID)
    }

    savedVTResults = localStorage.getItem("savedVTResults");
    //no savedVTResults
    if (!savedVTResults) {
        savedVTResults = [];
    }else {
        // load and parse savedVTResults -- This is the saved results from virus
        // total after we sent it for analysis.
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
       let finalResultsObjArr = JSON.parse(localStorage.getItem("finalResultsObjArr"));
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
        //console.log(response);
    });
   
}// end webSiteScan

    
        i++;
    });
    console.log(finalResultsObjArr);
    // lets save it
    localStorage.setItem("finalResultsObjArr", JSON.stringify(finalResultsObjArr));

   

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

    console.log(finalResultsObjArr);
    // lets save the new object array.
    // saved as   Engine Name :  Result   
    localStorage.setItem("finalResultsObjArr", JSON.stringify(finalResultsObjArr));

   

}


// async function request(url) {
//     const api_key = "4929f2c5-ed32-477f-b97e-bf05771c34a5";
//     const endpoint = "https://urlscan.io/api/v1/scan/";
//     const response =  await fetch(endpoint, {
//         method: "POST",
//         mode: "cors",
//         headers: {
//             'Content-Type': 'application/json',
//             'API-Key': api_key
//         },
//         body: JSON.stringify({
//             url: url
//         })
//     });

//     console.log(response);
//     return response.json();
// }

async function getNews(){
    let endpoint = " https://hacker-news.firebaseio.com/v0/beststories";

    let info = {
        "about" : "This is a test",
        "created" : 1173923446,
        "delay" : 0,
        "id" : "jl",
        "karma" : 2937,
        "submitted" : [ 8265435, 8168423, 8090946, 8090326, 7699907, 7637962, 7596179, 7596163, 7594569, 7562135, 7562111, 7494708, 7494171, 7488093, 7444860, 7327817, 7280290, 7278694, 7097557, 7097546, 7097254, 7052857, 7039484, 6987273, 6649999, 6649706, 6629560, 6609127, 6327951, 6225810, 6111999, 5580079, 5112008, 4907948, 4901821, 4700469, 4678919, 3779193, 3711380, 3701405, 3627981, 3473004, 3473000, 3457006, 3422158, 3136701, 2943046, 2794646, 2482737, 2425640, 2411925, 2408077, 2407992, 2407940, 2278689, 2220295, 2144918, 2144852, 1875323, 1875295, 1857397, 1839737, 1809010, 1788048, 1780681, 1721745, 1676227, 1654023, 1651449, 1641019, 1631985, 1618759, 1522978, 1499641, 1441290, 1440993, 1436440, 1430510, 1430208, 1385525, 1384917, 1370453, 1346118, 1309968, 1305415, 1305037, 1276771, 1270981, 1233287, 1211456, 1210688, 1210682, 1194189, 1193914, 1191653, 1190766, 1190319, 1189925, 1188455, 1188177, 1185884, 1165649, 1164314, 1160048, 1159156, 1158865, 1150900, 1115326, 933897, 924482, 923918, 922804, 922280, 922168, 920332, 919803, 917871, 912867, 910426, 902506, 891171, 807902, 806254, 796618, 786286, 764412, 764325, 642566, 642564, 587821, 575744, 547504, 532055, 521067, 492164, 491979, 383935, 383933, 383930, 383927, 375462, 263479, 258389, 250751, 245140, 243472, 237445, 229393, 226797, 225536, 225483, 225426, 221084, 213940, 213342, 211238, 210099, 210007, 209913, 209908, 209904, 209903, 170904, 165850, 161566, 158388, 158305, 158294, 156235, 151097, 148566, 146948, 136968, 134656, 133455, 129765, 126740, 122101, 122100, 120867, 120492, 115999, 114492, 114304, 111730, 110980, 110451, 108420, 107165, 105150, 104735, 103188, 103187, 99902, 99282, 99122, 98972, 98417, 98416, 98231, 96007, 96005, 95623, 95487, 95475, 95471, 95467, 95326, 95322, 94952, 94681, 94679, 94678, 94420, 94419, 94393, 94149, 94008, 93490, 93489, 92944, 92247, 91713, 90162, 90091, 89844, 89678, 89498, 86953, 86109, 85244, 85195, 85194, 85193, 85192, 84955, 84629, 83902, 82918, 76393, 68677, 61565, 60542, 47745, 47744, 41098, 39153, 38678, 37741, 33469, 12897, 6746, 5252, 4752, 4586, 4289 ]
      }

    let request = await fetch(endpoint, info)
    console.log(request);
    return request.json()
    
}




// Label the input button with id="inputButton" so
// it can be tied to this.
$("body").on("click", "#inputButton", function() {
    console.log(this);
});


// Function calls
initialLoad();// Call this to start the website.




// Listeners --We will probably use jquery so won't need them.



