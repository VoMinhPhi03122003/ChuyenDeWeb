import React, {Fragment} from "react";

const Post = () => {
    return (
        <Fragment>
            <div className="blog-details-top">
                <div className="blog-details-img">
                    <img
                        alt=""
                        src={process.env.PUBLIC_URL + "/assets/img/blog/blog-5.jpg"}
                    />
                </div>
                <div className="blog-details-content">
                    <div className="blog-meta-2">
                        <ul>
                            <li>22 April, 2018</li>
                        </ul>
                    </div>
                    <h3>14 Emerging Fashion Influencers Who Are Going to Own 2018</h3>
                    <p>
                        Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
                        eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
                        ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
                        aliquip ex ea commodo consequat. Duis aute irure dolor in reprhendit
                        in voluptate velit esse cillum dolore eu fugiat nulla pariatur.
                        Excepteur sint occaecat cupidatat non proident, sunt in culpa qei
                        officia deser mollit anim id est laborum. Sed ut perspiciatis unde
                        omnis iste natus error sit voluptatem accusantium doloremque
                        laudantium, totam rem aperiam.{" "}
                    </p>
                    <blockquote>
                        Lorem ipsum dolor sit amet, consecte adipisicing elit, sed do
                        eiusmod tempor incididunt labo dolor magna aliqua. Ut enim ad minim
                        veniam quis nostrud.
                    </blockquote>
                    <p>
                        Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
                        eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
                        ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
                        aliquip ex ea commodo consequat. Duis aute irure dolor in
                        reprehendrit in voluptate velit esse cillum dolore eu fugiat nulla
                        pariatur.
                    </p>
                </div>
            </div>
            <div className="dec-img-wrapper">
                <div className="row">
                    <div className="col-md-6">
                        <div className="dec-img mb-50">
                            <img
                                alt=""
                                src={
                                    process.env.PUBLIC_URL + "/assets/img/blog/blog-details.jpg"
                                }
                            />
                        </div>
                    </div>
                    <div className="col-md-6">
                        <div className="dec-img mb-50">
                            <img
                                alt=""
                                src={
                                    process.env.PUBLIC_URL + "/assets/img/blog/blog-details-2.jpg"
                                }
                            />
                        </div>
                    </div>
                </div>
                <p>
                    Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
                    eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad
                    minim veniam, quis nostrud exercitation ullamco laboris nisi ut
                    aliquip ex ea commodo consequat. Duis aute irure dolor in reprehendrit
                    in voluptate velit esse cillum dolore eu fugiat nulla pariatur.
                </p>
            </div>
            <div className="tag-share">
                <div className="blog-share">
                    <span>share :</span>
                    <div className="share-social">
                        <ul>
                            <li>
                                <a className="facebook" href="//facebook.com">
                                    <i className="fa fa-facebook"/>
                                </a>
                            </li>
                            <li>
                                <a className="twitter" href="//twitter.com">
                                    <i className="fa fa-twitter"/>
                                </a>
                            </li>
                            <li>
                                <a className="instagram" href="//instagram.com">
                                    <i className="fa fa-instagram"/>
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </Fragment>
    );
};

export default Post;